import os
import tempfile

import mock

from tests.unit import utils

from core import constants
from core.ycheck.scenarios import YScenarioChecker
from core.plugins.storage import bcache as bcache_core
from plugin_extensions.storage import bcache_summary


class StorageBCacheTestsBase(utils.BaseTestCase):

    def setup_bcachefs(self, path, bdev_error=False, cacheset_error=False):
        cset = os.path.join(path, 'sys/fs/bcache/1234')
        os.makedirs(cset)
        for cfg, val in {'congested_read_threshold_us': '0',
                         'congested_write_threshold_us': '0'}.items():
            with open(os.path.join(cset, cfg), 'w') as fd:
                if cacheset_error:
                    val = '100'

                fd.write(val)

        for cfg, val in {'cache_available_percent': '34'}.items():
            if cacheset_error:
                if cfg == 'cache_available_percent':
                    # i.e. >= 33 for lp1900438 check
                    val = '33'

            with open(os.path.join(cset, cfg), 'w') as fd:
                fd.write(val)

        bdev = os.path.join(cset, 'bdev1')
        os.makedirs(bdev)
        for cfg, val in {'sequential_cutoff': '0.0k',
                         'cache_mode':
                         'writethrough [writeback] writearound none',
                         'writeback_percent': '10'}.items():
            if bdev_error:
                if cfg == 'writeback_percent':
                    val = '1'

            with open(os.path.join(bdev, cfg), 'w') as fd:
                fd.write(val)

    def setUp(self):
        super().setUp()
        os.environ['PLUGIN_NAME'] = 'storage'


class TestBcacheBase(StorageBCacheTestsBase):

    def test_bcache_enabled(self):
        b = bcache_core.BcacheBase()
        self.assertTrue(b.bcache_enabled)

    def test_get_cachesets(self):
        path = os.path.join(constants.DATA_ROOT,
                            'sys/fs/bcache/d7696818-1be9-4dea-9991-'
                            'de95e24d7256')
        b = bcache_core.BcacheBase()
        self.assertEquals(b.get_cachesets(), [path])

    def test_get_cacheset_bdevs(self):
        b = bcache_core.BcacheBase()
        cset = b.get_cachesets()
        bdev0 = os.path.join(cset[0], 'bdev0')
        bdev1 = os.path.join(cset[0], 'bdev1')
        result = sorted(b.get_cacheset_bdevs(cset[0]))
        self.assertEqual(result, [bdev0, bdev1])

    def test_get_sysfs_cachesets(self):
        b = bcache_core.BcacheBase()
        expected = [{'cache_available_percent': 99,
                     'uuid': 'd7696818-1be9-4dea-9991-de95e24d7256'}]
        self.assertEqual(b.get_sysfs_cachesets(), expected)

    def test_udev_bcache_devs(self):
        b = bcache_core.BcacheBase()
        expected = [{'by-uuid': '88244ad9-372d-427e-9d82-c411c73d900a',
                     'name': 'bcache0'},
                    {'by-uuid': 'c3332949-19ba-40f7-91b6-48ee86157980',
                     'name': 'bcache1'}]

        self.assertEqual(b.udev_bcache_devs, expected)

    def test_is_bcache_device(self):
        b = bcache_core.BcacheBase()
        self.assertTrue(b.is_bcache_device('bcache0'))
        self.assertTrue(b.is_bcache_device('/dev/bcache0'))
        self.assertTrue(b.is_bcache_device('/dev/mapper/crypt-88244ad9-372d-'
                                           '427e-9d82-c411c73d900a'))


class TestStorageBCache(StorageBCacheTestsBase):

    def test_get_bcache_dev_info(self):
        result = {'bcache': {'bcache0': {'dname': 'bcache1'},
                             'bcache1': {'dname': 'bcache0'}}}
        inst = bcache_summary.BcacheSummary()
        actual = self.part_output_to_actual(inst.output)
        self.assertEqual(actual['devices'], result)

    def test_get_bcache_stats_checks(self):
        self.maxDiff = None
        expected = [{'cache_available_percent': 99,
                     'uuid': 'd7696818-1be9-4dea-9991-de95e24d7256'}]
        inst = bcache_summary.BcacheSummary()
        actual = self.part_output_to_actual(inst.output)
        self.assertEqual(actual['cachesets'], expected)


class TestBCacheScenarioChecks(StorageBCacheTestsBase):

    @mock.patch('core.plugins.storage.ceph.CephChecksBase.'
                'local_osds_use_bcache', True)
    @mock.patch('core.ycheck.YDefsLoader._is_def',
                new=utils.is_def_filter('juju_ceph_no_bcache_tuning.yaml'))
    @mock.patch('core.issues.issue_utils.add_issue')
    def test_juju_ceph_no_bcache_tuning(self, mock_add_issue):
        issues = []

        def fake_add_issue(issue):
            issues.append(issue)

        mock_add_issue.side_effect = fake_add_issue
        YScenarioChecker()()
        self.assertTrue(mock_add_issue.called)
        msgs = [("This host is running Juju-managed Ceph OSDs that are "
                 "using bcache devices yet the bcache-tuning charm was "
                 "not detected. It is recommended to use the "
                 "bcache-tuning charm to ensure optimal bcache "
                 "configuration.")]
        actual = sorted([issue.msg for issue in issues])
        self.assertEqual(actual, sorted(msgs))

    @mock.patch('core.ycheck.YDefsLoader._is_def',
                new=utils.is_def_filter('cacheset.yaml'))
    @mock.patch('core.issues.issue_utils.add_issue')
    def test_cacheset(self, mock_add_issue):
        issues = []

        def fake_add_issue(issue):
            issues.append(issue)

        mock_add_issue.side_effect = fake_add_issue
        with tempfile.TemporaryDirectory() as dtmp:
            self.setup_bcachefs(dtmp, cacheset_error=True)
            os.environ['DATA_ROOT'] = dtmp
            YScenarioChecker()()
            self.assertTrue(mock_add_issue.called)

            msgs = [('bcache cache_available_percent is 33 (i.e. approx. 30%) '
                     'which implies this node could be suffering from bug LP '
                     '1900438 - please check'),
                    ('bcache cacheset config congested_read_threshold_us '
                     'expected to be eq 0 but actual=100.')]
            actual = sorted([issue.msg for issue in issues])
            self.assertEqual(actual, sorted(msgs))

    @mock.patch('core.ycheck.YDefsLoader._is_def',
                new=utils.is_def_filter('bdev.yaml'))
    @mock.patch('core.issues.issue_utils.add_issue')
    def test_bdev(self, mock_add_issue):
        issues = []

        def fake_add_issue(issue):
            issues.append(issue)

        mock_add_issue.side_effect = fake_add_issue
        with tempfile.TemporaryDirectory() as dtmp:
            self.setup_bcachefs(dtmp, bdev_error=True)
            os.environ['DATA_ROOT'] = dtmp
            YScenarioChecker()()
            self.assertTrue(mock_add_issue.called)

            msgs = [('bcache config writeback_percent expected to be ge 10 '
                     'but actual=1.')]
            actual = sorted([issue.msg for issue in issues])
            self.assertEqual(actual, sorted(msgs))