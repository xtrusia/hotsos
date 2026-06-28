import os
import re
from datetime import datetime
from functools import cached_property

from hotsos.core import host_helpers, plugintools
from hotsos.core.config import HotSOSConfig
from hotsos.core.host_helpers.cli import CLIHelper
from hotsos.core.log import log
from hotsos.core.plugins.kernel.config import KernelConfig
from hotsos.core.plugins.system.system import SystemBase


# The kernel shipped with an Ubuntu release shares that release's support
# lifecycle, so an End-of-Life Ubuntu release implies an End-of-Life kernel.
# Dates are the standard support EOL for each release (LTS releases get
# additional ESM coverage which is not considered here). Source:
# https://endoflife.date/ubuntu and https://ubuntu.com/about/release-cycle
UBUNTU_EOL_INFO = {
    'resolute': datetime(2031, 4, 30),
    'questing': datetime(2026, 7, 1),
    'plucky': datetime(2026, 1, 17),
    'oracular': datetime(2025, 7, 10),
    'noble': datetime(2029, 5, 31),
    'mantic': datetime(2024, 7, 12),
    'lunar': datetime(2024, 1, 20),
    'kinetic': datetime(2023, 7, 20),
    'jammy': datetime(2027, 4, 1),
    'impish': datetime(2022, 7, 14),
    'hirsute': datetime(2022, 1, 20),
    'groovy': datetime(2021, 7, 22),
    'focal': datetime(2025, 5, 31),
    'eoan': datetime(2020, 7, 6),
    'disco': datetime(2020, 1, 23),
    'cosmic': datetime(2019, 7, 18),
    'bionic': datetime(2023, 5, 31),
    'artful': datetime(2018, 7, 19),
    'xenial': datetime(2021, 4, 2),
    'trusty': datetime(2019, 4, 2),
}


class KernelBase():
    """ Base class for kernel plugin helpers. """
    @cached_property
    def version(self):
        """Returns string kernel version."""
        uname = host_helpers.CLIHelper().uname()
        if uname:
            ret = re.compile(r"^Linux\s+\S+\s+(\S+)\s+.+").match(uname)
            if ret:
                return ret[1]

        return ""

    @cached_property
    def release_name(self):
        """Returns the Ubuntu release codename the kernel was shipped with."""
        # os_release_name returns e.g. "ubuntu focal" or None; we want the
        # bare codename for the UBUNTU_EOL_INFO lookup.
        osrel = SystemBase().os_release_name
        if not osrel:
            return "unknown"

        return osrel.split()[-1]

    @cached_property
    def days_to_eol(self):
        """
        Returns the number of days until the kernel reaches End of Life.

        The kernel inherits the support lifecycle of the Ubuntu release it
        was shipped with, so this is derived from that release's EOL date.
        """
        if self.release_name != 'unknown':
            eol = UBUNTU_EOL_INFO.get(self.release_name)
            if eol is not None:
                today = datetime.utcfromtimestamp(int(CLIHelper().date()))
                return (eol - today).days

        log.warning("unable to determine eol info for release name '%s' - "
                    "skipping kernel eol check", self.release_name)
        return None

    @cached_property
    def is_eol(self):
        """Return True if the kernel's Ubuntu release is known to be EOL."""
        days_to_eol = self.days_to_eol
        if days_to_eol is None:
            return False

        return days_to_eol <= 0

    @cached_property
    def isolcpus_enabled(self):
        """Return True if isolcpus is configured in kernel parameters."""
        return KernelConfig().get('isolcpus') is not None

    @cached_property
    def boot_parameters(self):
        """Returns list of boot parameters."""
        parameters = []
        path = os.path.join(HotSOSConfig.data_root, "proc/cmdline")
        if os.path.exists(path):
            with open(path, encoding='utf-8') as fd:
                cmdline = fd.read().strip()
            for entry in cmdline.split():
                if entry.startswith("BOOT_IMAGE"):
                    continue

                if entry.startswith("root="):
                    continue

                parameters.append(entry)

            return parameters

        return None


class KernelChecks(KernelBase, plugintools.PluginPartBase):
    """ Base class for all kernel checks. """
    plugin_name = 'kernel'
    plugin_root_index = 1000

    @classmethod
    def is_runnable(cls):
        """
        Determine whether or not this plugin can and should be run.

        @return: True or False
        """
        return True
