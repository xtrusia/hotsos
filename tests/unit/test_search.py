import datetime

from hotsos.core.search import CommonTimestampMatcher

from . import utils


class TestCommonTimestampMatcher(utils.BaseTestCase):
    """ Unit tests for CommonTimestampMatcher. """

    def test_openstack(self):
        """ Default oslo.log format. """
        line = ('2022-02-10 10:28:35.123 1234 ERROR keystone.common.'
                'fernet_utils [-] Either [fernet_tokens] key_repository ...')
        matcher = CommonTimestampMatcher(line)
        self.assertTrue(matcher.matched)
        self.assertEqual(matcher.strptime,
                         datetime.datetime(2022, 2, 10, 10, 28, 35))

    def test_logger_prefixed(self):
        """ Format used by the keystone charm's logging.conf. """
        line = ('(keystone.common.fernet_utils): 2022-02-10 10:28:35,123 '
                'ERROR Either [fernet_tokens] key_repository does not exist')
        matcher = CommonTimestampMatcher(line)
        self.assertTrue(matcher.matched)
        self.assertEqual(matcher.strptime,
                         datetime.datetime(2022, 2, 10, 10, 28, 35))

    def test_logger_prefixed_no_match(self):
        """ Prefix must be at the start and followed by a date. """
        for line in ['(keystone.common.fernet_utils) 2022-02-10 10:28:35,123',
                     'foo (keystone): 2022-02-10 10:28:35,123 ERROR bar',
                     '(keystone): Feb 10 10:28:35 ERROR bar']:
            self.assertFalse(CommonTimestampMatcher(line).matched)
