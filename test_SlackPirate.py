import unittest

import SlackPirate as m  # M is for module!
from mock import patch

class SlackPirateTestSuite(unittest.TestCase):

    @patch('SlackPirate.time.sleep')
    def test_sleep_if_needed(self, mock_sleep):
        """Verifies that a rate-limited response triggers a sleep"""
        normal_response = dict(ok=True)
        different_error_response = dict(ok=False, error='sessionExpired')
        rate_limited_response = dict(ok=False, error=m.ERROR_RATE_LIMITED)

        m.sleep_if_needed(normal_response)
        self.assertFalse(mock_sleep.called)

        m.sleep_if_needed(different_error_response)
        self.assertFalse(mock_sleep.called)

        m.sleep_if_needed(rate_limited_response)
        self.assertTrue(mock_sleep.called)