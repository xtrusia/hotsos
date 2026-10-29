import gzip
import os
import tempfile
from datetime import datetime

from searchkit.constraints import CouldNotApplyConstraint
from hotsos.core.config import HotSOSConfig
from hotsos.core.search import (
    CommonTimestampMatcher,
    ExtraSearchConstraints,
    FileSearcher,
    SearchConstraintSearchSince,
    SearchDef,
)
from tools.validation.hotyvalidate import SearchExpressionValidator

from . import utils


LOGRUS_EXPR = (r'^time="(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
               r'(?:Z|[+-]\d{2}:\d{2}))" level=warning')


class TestLogrusTimestamps(utils.BaseTestCase):
    """Logrus's default non-colour text timestamps, as used by LXD."""

    @staticmethod
    def log_line(timestamp):
        """Keep the quoted timestamp and fixed fields in writer order."""
        return (f'time="{timestamp}" level=warning '
                'msg="Failed auto start instance attempt"\n')

    def test_timezone(self):
        """Use UTC for Z and signed offsets, including date rollover."""
        for timestamp in ('2022-02-09T16:19:18Z',
                          '2022-02-10T01:19:18+09:00',
                          '2022-02-09T12:19:18-04:00'):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(
                    CommonTimestampMatcher(self.log_line(timestamp)).strptime,
                    datetime(2022, 2, 9, 16, 19, 18))

    def test_age_boundary(self):
        """Compare the complete offset timestamp at a 24-hour boundary."""
        constraint = SearchConstraintSearchSince(
            ts_matcher_cls=CommonTimestampMatcher, hours=24)
        for timestamp, expected in (
                ('2022-02-09T16:19:16Z', False),
                ('2022-02-09T16:19:17Z', True),
                ('2022-02-10T01:19:16+09:00', False),
                ('2022-02-10T01:19:17+09:00', True),
                ('2022-02-09T12:19:16-04:00', False),
                ('2022-02-09T12:19:17-04:00', True)):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(constraint.apply_to_line(
                    self.log_line(timestamp)), expected)

    def test_malformed_timestamp(self):
        """Reject missing quotes, incomplete offsets and invalid offsets."""
        lines = [self.log_line(f'2022-02-09T16:19:18{offset}')
                 for offset in ('', '+24:00', '-24:00', '+01:60', '-00:99',
                                '+1:00', '+0100', '+01:00:00', 'Zjunk')]
        lines.extend(('time="2022-02-09T16:19:18Z level=warning\n',
                      'time=2022-02-09T16:19:18Z level=warning\n',
                      'time="2022-02-09T16:19:18Z"junk level=warning\n'))
        constraint = SearchConstraintSearchSince(
            ts_matcher_cls=CommonTimestampMatcher, hours=24)
        for line in lines:
            with self.subTest(line=line):
                self.assertFalse(CommonTimestampMatcher(line).matched)
                self.assertRaises(CouldNotApplyConstraint,
                                  constraint.apply_to_line, line)

    def test_file_and_search_constraints(self):
        """Filter ordered mixed-format files and a compressed rotation."""
        HotSOSConfig.use_all_logs = True
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'lxd.log')
            with gzip.open(f'{path}.1.gz', 'wt') as stream:
                stream.write(self.log_line('2022-02-08T16:19:18Z'))
                stream.write(self.log_line('2022-02-09T16:19:16Z'))
                stream.write(self.log_line('2022-02-09T16:19:17Z'))
            with open(path, 'w', encoding='utf-8') as stream:
                stream.write('2022-02-09T16:19:18Z host: message\n')
                stream.write(self.log_line('2022-02-10T01:19:19+09:00'))
                stream.write(self.log_line('2022-02-10T15:19:18Z'))

            global_constraint = SearchConstraintSearchSince(
                ts_matcher_cls=CommonTimestampMatcher, hours=24)
            searcher = FileSearcher(constraint=global_constraint)
            searcher.add(SearchDef(r'^(.*)$', tag='global'), f'{path}*')
            searcher.add(SearchDef(
                LOGRUS_EXPR, tag='per-search',
                constraints=[SearchConstraintSearchSince(
                    ts_matcher_cls=CommonTimestampMatcher, hours=12)]),
                f'{path}*')
            results = searcher.run()
            self.assertEqual(len(results.find_by_tag('global')), 4)
            self.assertEqual([result.get(1) for result in
                              results.find_by_tag('per-search')],
                             ['2022-02-10T15:19:18Z'])

    def test_result_period(self):
        """Keep group one's offset when ordering results by UTC."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as stream:
            stream.write(self.log_line('2022-02-10T01:19:18+09:00'))
            stream.write(self.log_line('2022-02-09T12:49:18-04:00'))
            stream.write(self.log_line('2022-02-09T14:49:17Z'))
            stream.flush()
            searcher = FileSearcher()
            searcher.add(SearchDef(LOGRUS_EXPR, tag='logrus'), stream.name)
            results = searcher.run().find_by_tag('logrus')
            filtered = ExtraSearchConstraints.filter_by_period(results, 1)
            self.assertEqual([result.get(1) for result in filtered],
                             ['2022-02-09T12:49:18-04:00',
                              '2022-02-10T01:19:18+09:00'])

    def test_live_bypasses_age(self):
        """Preserve the documented bypass for roots without sos_commands."""
        constraint = SearchConstraintSearchSince(
            ts_matcher_cls=CommonTimestampMatcher, hours=24)
        with tempfile.TemporaryDirectory() as root:
            HotSOSConfig.data_root = root
            self.assertTrue(constraint.apply_to_line(
                self.log_line('2000-01-01T00:00:00Z')))
            with tempfile.NamedTemporaryFile(mode='w+') as stream:
                stream.write(self.log_line('2000-01-01T00:00:00Z'))
                stream.seek(0)
                self.assertEqual(constraint.apply_to_file(stream), 0)

    def test_validator(self):
        """Preserve the full ISO timestamp in the first capture."""
        loose = LOGRUS_EXPR.replace(r'\d{2}:\d{2}:\d{2}', r'[\d:]+')
        for pattern in (LOGRUS_EXPR, LOGRUS_EXPR[1:], loose, loose[1:]):
            with self.subTest(pattern=pattern):
                self.assertTrue(
                    SearchExpressionValidator.is_compliant(pattern))
        for pattern in (r'^time="(\d{4}-\d{2}-\d{2})',
                        r'^time="(?:\d{4}-\d{2}-\d{2}T\S+)" (.*)',
                        r'^time="(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"'):
            with self.subTest(pattern=pattern):
                self.assertFalse(
                    SearchExpressionValidator.is_compliant(pattern))
