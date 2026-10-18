import abc
import bisect
import re

from hotsos.core.log import log
from hotsos.core.search import (
    CommonTimestampMatcher,
    SearchDef,
    SequenceSearchDef,
)
from hotsos.core.plugins.kernel.kernlog.common import (
    CallTraceHeuristicBase,
    CallTraceStateBase,
    TraceTypeBase,
    KernLogBase,
)

KERNLOG_TS = r'\[\s*\d+\.\d+\]'
KERNLOG_PREFIX = rf'(?:\S+\s+\d+\s+[\d:]+\s+\S+\s+\S+:\s+)?{KERNLOG_TS}'
# Leading date of a kernel log line: 'Feb 10' (legacy syslog, journalctl) or
# '2022-02-10' (RFC3339 rsyslog format).
LOG_DATE_EXPR = r'(\w{3,5}\s+\d{1,2}|\d{4}-\d{2}-\d{2})[T ][\d:]+\S* '


def join_dates(dates):
    """
    Comma separated unique dates in calendar order. The syslog format has no
    year, so those dates sort by month and day before the RFC3339 ones.
    """
    def key(date):
        if '-' in date:
            year, month, day = date.split('-')
            return int(year), int(month), int(day), date

        month, day = date.split()
        month = CommonTimestampMatcher.MONTH_MAP.get(month[:3].lower(), 0)
        return 0, month, int(day), date

    return ', '.join(sorted({' '.join(d.split()) for d in dates if d},
                            key=key))


class OOMTraceHeuristicCheckFreePages(CallTraceHeuristicBase):
    """
    Defines a basic memory check heuristic using information extracted from
    an OOM kill call trace.
    """
    def __init__(self, state):
        """
        @param state: an OOMCallTraceState object.
        """
        self.node = state.node_id
        self.zone = state.node_zone
        self.free = state.free
        self.min = state.min
        self.low = state.low

    def __call__(self):
        """
        Returns a list of strings representing failures.
        """
        fails = []
        if self.free < self.min:
            fails.append(f"Node {self.node} zone {self.zone} free pages "
                         f"{self.free} below min {self.min}")
        elif self.free < self.low:
            fails.append(f"Node {self.node} zone {self.zone} free pages "
                         f"{self.free} below low {self.low}")

        return fails


class OOMCallTraceState(CallTraceStateBase):
    """ Representation of OOM call trace state. """
    def __repr__(self):
        """
        Provide a nice way to view the state e.g. in debug logs.
        """
        prefix = ""
        if self.node_id:
            prefix = " -> "

        s = []
        for k, v in self._info.items():
            if k == 'nodes':
                s.append(f"{prefix}{k}:")
                for node, zones in v.items():
                    s.append(f">> node{node}")
                    for zone, fields in zones.items():
                        s.append(f" {zone}: {repr(fields)}")
            else:
                s.append(f"{prefix}{k}: {v}")

        # can't use formatted string with backslash < py312
        return "\n{}\n".format('\n'.join(s))  # noqa, pylint: disable=consider-using-f-string


class GenericTraceType(TraceTypeBase):
    """
    Used to identify call traces of any type.

    This is mainly useful for high level checks like whether or not any call
    traces have occurred.
    """

    def __init__(self):
        self._search_def = None
        self.generics = []

    @property
    def name(self):
        return 'calltrace-anytype'

    @property
    def searchdef(self):
        if self._search_def:
            return self._search_def

        # Very basic, just a simple expression to identify that a call trace
        # has occurred.
        expr = rf'^(?:{LOG_DATE_EXPR})?.+Call Trace:'
        self._search_def = SearchDef(expr, tag=self.name)
        return self._search_def

    def apply(self, results):
        """
        Run through the results.

        @param results: list of search.SearchResult objects.
        """
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        for trace in results:
            # save the location and date so that the list length represents
            # the number of call traces.
            self.generics.append((trace.source_id, trace.linenumber,
                                  trace.get(1)))

    @property
    def heuristics(self):
        """
        Register any heuristics we want to run here.
        """
        return []

    def __len__(self):
        return len(self.generics)

    def __iter__(self):
        yield from self.generics


class MemFieldsBase():
    """
    Provides a common way to identify fields in an oom kill trace and extract
    their values.
    """

    def extract(self, part, line):
        """ Extract memory field values from a trace line. """
        for field in self.fields:
            ret = re.search(f'{field}:{self.expr}', line)
            if ret:
                part.add(field, ret.group(1))

    @property
    @abc.abstractmethod
    def expr(self):
        """ Search pattern template used to match a field and its value. """

    @property
    @abc.abstractmethod
    def fields(self):
        """ List of fields we want extract from a given section. """


class MemFieldsMain(MemFieldsBase):
    """
    Expression and fields for extracting process memory information from call
    traces.
    """
    @property
    def expr(self):
        return r'\s?(\d+)'

    @property
    def fields(self):
        return ['active_anon', 'inactive_anon', 'isolated_anon',
                'active_file', 'inactive_file', 'isolated_file', 'unevictable',
                'dirty', 'writeback', 'slab_reclaimable', 'slab_unreclaimable',
                'mapped', 'shmem', 'pagetables', 'bounce', 'free', 'free_pcp',
                'free_cma']


class MemFieldsNodeMem(MemFieldsBase):
    """
    Expression and fields for extracting process numa node-specific memory
    information from call traces.
    """
    @property
    def expr(self):
        return r'\s?(\d+)kB'

    @property
    def fields(self):
        # not all kernels have all these fields
        return ['active_anon', 'inactive_anon', 'active_file',
                'inactive_file', 'unevictable', r'isolated\(anon\)',
                r'isolated\(file\)', 'mapped', 'dirty', 'writeback', 'shmem',
                'shmem_thp', 'shmem_pmdmapped', 'anon_thp', 'writeback_tmp',
                'kernel_stack', 'pagetables', 'writeback_tmp', 'unstable']


class MemFieldsNodeUNRC(MemFieldsBase):
    """
    Expression and fields for extracting process unreclaimable memory
    information from call traces.
    """
    @property
    def expr(self):
        return r'\s?([a-z]+)$'

    @property
    def fields(self):
        return [r'all_unreclaimable\?']


class MemFieldsNodeZoneMem(MemFieldsBase):
    """
    Expression and fields for extracting process numa node-zone-specific memory
    information from call traces.
    """
    @property
    def expr(self):
        return r'\s?(\d+)[Kk]B'

    @property
    def fields(self):
        return ['free', 'min', 'low', 'high',
                'reserved_highatomic', 'active_anon', 'inactive_anon',
                'active_file', 'inactive_file', 'unevictable', 'writepending',
                'present', 'managed', 'mlocked', 'bounce', 'free_pcp',
                'local_pcp', 'free_cma']


class BcacheDeadlockType(TraceTypeBase):
    """
    Implementation of traceback analysis for bcache deadlocks.
    """
    def __init__(self):
        self._search_def = None
        self.deadlocks = []

    @property
    def name(self):
        return 'calltrace-bcache'

    @property
    def searchdef(self):
        if self._search_def:
            return self._search_def

        start = SearchDef(rf'{KERNLOG_PREFIX}.+\s+task bcache-register:(\d+) '
                          r'blocked for more than (\d+) seconds.')
        body = SearchDef(r'(\S+) schedule(\S+) closure_sync(\S+)'
                         r' bch_journal_meta(\S+) bch_btree_set_root(\S+)'
                         r' bch_journal_replay(\S+) register_bcache(\S+)')
        end = SearchDef(rf'{KERNLOG_PREFIX}.+\s+do_syscall_(\S+)')
        self._search_def = SequenceSearchDef(start, tag='bcache', body=body,
                                             end=end)
        return self._search_def

    def apply(self, results):
        """
        Run through the results.
        @param results: list of search.SearchResult objects.
        """
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        if len(results) > 0:
            # we have found at least one deadlock
            self.deadlocks.append(True)

    @property
    def heuristics(self):
        """
        Register any heuristics we want to run here.
        """
        return []

    def __len__(self):
        return len(self.deadlocks)

    def __iter__(self):
        yield from self.deadlocks


class FanotifyDeadlockType(TraceTypeBase):
    """
    Implementation of traceback analysis for fanotify deadlocks.
    """
    def __init__(self):
        self._search_def = None
        self.fanotify_hangs = []

    @property
    def name(self):
        return 'calltrace-fanotify'

    @property
    def searchdef(self):
        if self._search_def:
            return self._search_def

        start = SearchDef(r'.+ blocked for more than (\d+) seconds.')
        body = SearchDef(r'(\S+) schedule(\S+) fanotify_handle_event(\S+)'
                         r' fsnotify(\S+)')
        end = SearchDef(r'.+\s+do_sys_open(\S+)')
        self._search_def = SequenceSearchDef(start, tag='fanotify', body=body,
                                             end=end)
        return self._search_def

    def apply(self, results):
        """
        Run through the results.
        @param results: list of search.SearchResult objects.
        """
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        if len(results) > 0:
            # we have found at least one fanotify related hang
            self.fanotify_hangs.append(True)

    @property
    def heuristics(self):
        """
        Register any heuristics we want to run here.
        """
        return []

    def __len__(self):
        return len(self.fanotify_hangs)

    def __iter__(self):
        yield from self.fanotify_hangs


class OOMKillerTraceType(TraceTypeBase):
    """
    Implementation of traceback analysis for OOM tracebacks.
    """
    def __init__(self):
        self._search_def = None
        self.oom_traces = []

    @property
    def name(self):
        return 'oom-killer'

    @property
    def searchdef(self):
        if self._search_def:
            return self._search_def

        start = SearchDef(rf'{KERNLOG_PREFIX} (\S+) invoked oom-killer: .+, '
                          r'order=([+-]?\d+),.+')

        fields = set()
        for mfieldtype in [MemFieldsMain, MemFieldsNodeZoneMem,
                           MemFieldsNodeMem, MemFieldsNodeUNRC]:
            fields.update(mfieldtype().fields)

        # Only include lines that actually contain fields we want to extract
        body = SearchDef(rf"(.+(?:{'|'.join(fields)}).+)")
        # NOTE: we need a better way to capture the different variations of
        #       the following message.
        end = SearchDef(rf'{KERNLOG_PREFIX} '
                        r'(?:Out of memory: |Memory cgroup out of memory: )?'
                        r'Killed process (\d+) .+')
        self._search_def = SequenceSearchDef(start, tag='oom', body=body,
                                             end=end)
        return self._search_def

    def apply(self, results):
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        for trace in results.values():
            oom_kill = OOMCallTraceState()
            oom_kill.add('nodes', {})
            current_node = None
            for item in trace:
                if item.tag.endswith('-start'):
                    oom_kill.add('procname', item.get(1))
                    oom_kill.add('order', item.get(2))
                elif item.tag.endswith('-body'):
                    # There will be one or more of these.
                    line = item.get(1)

                    ret = re.search(r"Node (\d+) active_anon:", line)
                    if ret:
                        current_node = OOMCallTraceState()
                        node_id = ret.group(1)
                        current_node.add('node_id', node_id)
                        oom_kill.nodes[node_id] = {'main': current_node}
                    else:
                        ret = re.search(r"Node (\d+) (\S+) free:", line)
                        if ret:
                            current_node = OOMCallTraceState()
                            node_id = ret.group(1)
                            node_zone = ret.group(2)
                            current_node.add('node_id', node_id)
                            current_node.add('node_zone', node_zone)
                            oom_kill.nodes[node_id][node_zone] = current_node

                    if not current_node:
                        MemFieldsMain().extract(oom_kill, line)
                    elif current_node.node_zone:
                        MemFieldsNodeZoneMem().extract(current_node, line)
                    else:
                        MemFieldsNodeMem().extract(current_node, line)
                        MemFieldsNodeUNRC().extract(current_node, line)
                else:
                    # end
                    oom_kill.add('pid', item.get(1))

            log.info(oom_kill)
            self.oom_traces.append(oom_kill)

    @property
    def heuristics(self):
        _heuristics = []
        for oom_trace in self.oom_traces:
            for node, zones in oom_trace.nodes.items():
                if node is None:
                    continue

                for zone, state in zones.items():
                    if zone == 'main':
                        continue

                    _heuristics.append(OOMTraceHeuristicCheckFreePages(state))

        return _heuristics

    def __len__(self):
        return len(self.oom_traces)

    def __iter__(self):
        yield from self.oom_traces


class HungtaskTraceType(TraceTypeBase):
    """
    Implementation of traceback analysis for hung task tracebacks.
    """
    def __init__(self):
        self._search_def = None
        self.hungtasks = []

    @property
    def name(self):
        return 'calltrace-hungtask'

    @property
    def searchdef(self):
        if self._search_def:
            return self._search_def

        start = SearchDef(r'.+ blocked for more than (\d+) seconds.')
        # We don't need the body so don't match/save it
        body = None
        end = SearchDef(r'.+\s+do_syscall_(\S+)')
        self._search_def = SequenceSearchDef(start, tag='hungtask', body=body,
                                             end=end)
        return self._search_def

    def apply(self, results):
        """
        Run through the results.
        @param results: list of searchtools.SearchResult objects.
        """
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        if len(results) > 0:
            # we have found at least one blocked task
            self.hungtasks.append(True)

    @property
    def heuristics(self):
        """
        Register any heuristics we want to run here.
        """
        return []

    def __len__(self):
        return len(self.hungtasks)

    def __iter__(self):
        yield from self.hungtasks


class SimpleTraceTypeBase(TraceTypeBase):
    """
    Base class for trace types that are identified by a single kern.log line
    and where we only need to count the number of occurrences. The line is
    typically followed by a call trace that the GenericTraceType also counts.
    Implementations must provide name and expr. The leading timestamp of the
    line (legacy syslog or RFC3339 date) is saved for each occurrence.
    """
    # Group 1 is the date.
    DATE_EXPR = '^' + LOG_DATE_EXPR
    # Maximum number of lines between a report and its first call trace.
    first_trace_max_lines = 100

    def __init__(self):
        self._search_def = None
        self.traces = []
        # (source_id, linenumber, has_call_trace) of each occurrence
        self.reports = []

    @property
    @abc.abstractmethod
    def expr(self):
        """ Regular expression that identifies one occurrence. """

    @property
    def searchdef(self):
        if self._search_def is None:
            self._search_def = SearchDef(self.DATE_EXPR + self.expr,
                                         tag=self.name)

        return self._search_def

    def apply(self, results):
        """
        Run through the results.
        @param results: list of search.SearchResult objects.
        """
        log.debug("%s has %s results", self.__class__.__name__, len(results))
        for result in results:
            # save the date so that the list length represents the number of
            # occurrences.
            self.traces.append(result.get(1))
            self.reports.append((result.source_id, result.linenumber,
                                 self.has_call_trace(result)))

    @staticmethod
    def has_call_trace(result):  # pylint: disable=unused-argument
        """ Whether the kernel prints a call trace after this report. """
        return True

    @property
    def dates(self):
        """ Comma separated unique dates of the occurrences. """
        return join_dates(self.traces)

    @property
    def heuristics(self):
        """
        Register any heuristics we want to run here.
        """
        return []

    def __len__(self):
        return len(self.traces)

    def __iter__(self):
        yield from self.traces


class SoftLockupTraceType(SimpleTraceTypeBase):
    """
    Soft lockup reports from the kernel watchdog (kernel/watchdog.c), with or
    without the 'watchdog: ' or 'NMI watchdog: ' pr_fmt prefix.
    """
    @property
    def name(self):
        return 'calltrace-softlockup'

    @property
    def expr(self):
        return r'.+ BUG: soft lockup - CPU#\d+ stuck for \d+s!'


class RcuStallTraceType(SimpleTraceTypeBase):
    """
    RCU CPU stall warning headers (kernel/rcu/tree_stall.h).
    """
    # A stall warning prints up to four lines for each stalled CPU before
    # the call traces.
    first_trace_max_lines = 1000

    @property
    def name(self):
        return 'calltrace-rcustall'

    @property
    def expr(self):
        return (r'.+ INFO: rcu_\w+ (?:self-detected stall on CPU|'
                r'detected stalls on CPUs/tasks)')


class BadPageStateTraceType(SimpleTraceTypeBase):
    """
    Bad page state reports from bad_page() (mm/page_alloc.c).
    """
    @property
    def name(self):
        return 'calltrace-badpagestate'

    @property
    def expr(self):
        return r'.+ BUG: Bad page state in process .+  pfn:[0-9a-f]+'


class PageAllocFailureTraceType(SimpleTraceTypeBase):
    """
    Page allocation failure reports from warn_alloc() (mm/page_alloc.c).
    """
    @property
    def name(self):
        return 'calltrace-pageallocfailure'

    @property
    def expr(self):
        return (r'.+: page allocation failure: order:\d+, '
                r'mode:0x[0-9a-f]+')


class NetdevWatchdogTraceType(SimpleTraceTypeBase):
    """
    Transmit queue timeouts reported by dev_watchdog()
    (net/sched/sch_generic.c). Kernels before mainline 6.8 (without the
    stable backport, e.g. in 6.1.107) report this with WARN_ONCE
    so the first one is followed by a call trace. The interfaces are saved as
    '<interface> (<driver>)', or '<interface>' when the line has no driver.
    """
    @property
    def name(self):
        return 'calltrace-netdevwatchdog'

    def __init__(self):
        super().__init__()
        self.ifnames = []

    @property
    def expr(self):
        # Mainline 6.8 and later (and stable backports): netdev_crit()
        # prefix '<driver> <bus id> <ifname>: '
        # (only '<ifname>: ' without a parent device); earlier kernels:
        # 'NETDEV WATCHDOG: <ifname> (<driver>): ' where the driver name can
        # be empty. netdev_reg_state() can add a suffix such as
        # ' (unregistering)' to the netdev_crit() ifname.
        return (r'.+ kernel: (?:\[[^\]]*\] )?'
                r'(?:(?:(\S+) \S+ )?(\S+)(?: \([a-z]+\))?: '
                r'NETDEV WATCHDOG: CPU: \d+|'
                r'NETDEV WATCHDOG: (\S+) \((\S*)\)): '
                r'transmit queue \d+ timed out')

    def apply(self, results):
        super().apply(results)
        for result in results:
            if result.get(3):
                ifname, driver = result.get(3), result.get(2)
            else:
                ifname, driver = result.get(4), result.get(5)

            self.ifnames.append(f"{ifname} ({driver})" if driver else ifname)

    @staticmethod
    def has_call_trace(result):
        # The netdev_crit() form (group 3 set) has no call trace.
        return not result.get(3)

    @property
    def interfaces(self):
        """ Sorted unique interfaces (with driver) that timed out. """
        return sorted(set(self.ifnames))


class CallTraceManager(KernLogBase):
    """
    Manager for all call trace analysis types. From here all analysis is run
    and results collected.
    """
    # Maximum number of lines between a call trace that is part of a report
    # and the next one.
    OTHER_TRACE_MAX_LINES = 100
    # Lines that start another report with its own call trace: WARN() and
    # BUG() ('cut here'), OOM kills and hung tasks (their call traces are
    # only part of them if the existing types counted them), x86 and arm64
    # oopses, hard lockups, panics and the scheduler atomic context bugs.
    # The user space 'traps: ... general protection fault ip:...' line is
    # not matched.
    REPORT_START_EXPR = (r'.+(?:------------\[ cut here \]------------|'
                         r' invoked oom-killer: |'
                         r' blocked for more than \d+ seconds|'
                         r'BUG: unable to handle |'
                         r'Unable to handle kernel |'
                         r'Internal error: Oops|'
                         r'BUG: kernel NULL pointer dereference|'
                         r'general protection fault[:,] |'
                         r'Watchdog detected hard LOCKUP|'
                         r'Kernel panic - not syncing|'
                         r'BUG: scheduling while atomic|'
                         r'BUG: sleeping function called from invalid '
                         r'context)')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.other_traces = []
        # (source_id, linenumber) of the start of each report that an
        # existing SequenceSearchDef type (OOM killer, hung task, bcache or
        # fanotify deadlock) matched and counted.
        self.known_reports = []
        self._report_start_def = SearchDef(self.REPORT_START_EXPR,
                                           tag='calltrace-report-start')
        # All trace types should be registered here.
        self.tracetypes = [GenericTraceType(), OOMKillerTraceType(),
                           BcacheDeadlockType(), HungtaskTraceType(),
                           FanotifyDeadlockType(), SoftLockupTraceType(),
                           RcuStallTraceType(), BadPageStateTraceType(),
                           PageAllocFailureTraceType(),
                           NetdevWatchdogTraceType()]
        self.run()

    def run(self):
        """ Search for call traces and apply matching trace types. """
        self.results = self.perform_search([t.searchdef
                                            for t in self.tracetypes] +
                                           [self._report_start_def])
        if not self.results:
            return

        for tracetype in self.tracetypes:
            if isinstance(tracetype.searchdef, SequenceSearchDef):
                results = self.results.find_sequence_sections(
                                                           tracetype.searchdef)
                tracetype.apply(results)
                if len(tracetype):
                    self.known_reports.extend(
                        (item.source_id, item.linenumber)
                        for section in results.values() for item in section
                        if item.tag.endswith('-start'))
            else:
                results = self.results.find_by_tag(tracetype.searchdef.tag)
                tracetype.apply(results)

        self._find_other_traces()

    def _find_other_traces(self):
        """
        Find the call traces that are not part of a report of a
        SimpleTraceTypeBase type, if at least one such report was found
        (otherwise the generic 'stacktraces' conclusion is raised for all of
        them).
        """
        simple = [t for t in self.tracetypes
                  if isinstance(t, SimpleTraceTypeBase)]
        if not any(len(t) for t in simple):
            return

        # (linenumber, max lines to the first call trace) of the reports
        # that print call traces, by source.
        reports = {}
        for tracetype in simple:
            for source_id, linenumber, has_call_trace in tracetype.reports:
                if has_call_trace:
                    reports.setdefault(source_id, []).append(
                        (linenumber, tracetype.first_trace_max_lines))

        for source_id, linenumber in self.known_reports:
            reports.setdefault(source_id, []).append(
                (linenumber, SimpleTraceTypeBase.first_trace_max_lines))

        starts = {}
        for result in self.results.find_by_tag(self._report_start_def.tag):
            starts.setdefault(result.source_id, []).append(result.linenumber)

        for lines in list(reports.values()) + list(starts.values()):
            lines.sort()

        last_trace = {}
        for trace in sorted(self.calltrace_anytype.generics):
            report = self._report_of(trace[1], reports.get(trace[0], []),
                                     starts.get(trace[0], []),
                                     last_trace.get(trace[0], {}))
            if report is None:
                self.other_traces.append(trace)
            else:
                last_trace.setdefault(trace[0], {})[report] = trace[1]

    def _report_of(self, linenumber, reports, starts, last_trace):
        """
        Return the line number of the report that the call trace at
        linenumber is part of, or None.

        A call trace is part of the closest preceding report in the same
        source that prints call traces (a SimpleTraceTypeBase report or a
        report counted by an existing OOM killer, hung task, bcache or
        fanotify deadlock type) if it is at most
        first_trace_max_lines lines after the report or at most
        OTHER_TRACE_MAX_LINES lines after the last call trace that is part
        of it (an RCU stall prints one for each CPU) and no line that starts
        another report (REPORT_START_EXPR) is in between.

        @param reports: sorted (linenumber, first_trace_max_lines) of the
                        reports in the source.
        @param starts: sorted line numbers of REPORT_START_EXPR lines in the
                       source.
        @param last_trace: line number of the last call trace that is part
                           of each report in the source.
        """
        index = bisect.bisect_left(reports, (linenumber,)) - 1
        if index < 0:
            return None

        report, max_lines = reports[index]
        anchor = last_trace.get(report)
        if anchor is None:
            anchor = report
        else:
            max_lines = self.OTHER_TRACE_MAX_LINES

        start = bisect.bisect_right(starts, anchor)
        if linenumber - anchor > max_lines or (start < len(starts) and
                                               starts[start] < linenumber):
            return None

        return report

    @property
    def other_stacktraces(self):
        """
        Call traces that are not part of a report of one of the
        SimpleTraceTypeBase types, when at least one such report was found.
        """
        return self.other_traces

    @property
    def other_stacktraces_dates(self):
        """ Comma separated dates of other_stacktraces. """
        return join_dates(trace[2] for trace in self.other_traces)

    @property
    def netdev_watchdog_interfaces(self):
        """ Comma separated interfaces named in NETDEV WATCHDOG reports. """
        return ', '.join(self.calltrace_netdevwatchdog.interfaces)

    def __getattr__(self, name):
        """
        If one or more trace has been identified with the given type name,
        return its object. '<type name>_dates' returns the dates of a
        SimpleTraceTypeBase type.
        """
        if name.endswith('_dates'):
            tracetype = getattr(self, name[:-len('_dates')])
            return getattr(tracetype, 'dates', None)

        for h in self.tracetypes:
            if h.name == name.replace('_', '-'):
                return h

        return None
