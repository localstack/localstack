import unittest

from localstack.services.logs.logs_listener import log_events_match_filter_pattern


class CloudWatchLogsTest(unittest.TestCase):
    def test_filter_expressions(self):
        def assert_match(pattern, log_events, expected):
            result = log_events_match_filter_pattern(pattern, log_events)
            self.assertTrue(result) if expected else self.assertFalse(result)

        log_events = [{"message": "test123"}, {"message": "foo bar 456"}]
        assert_match("*", log_events, True)
        assert_match("", log_events, True)
        assert_match("INVALID", log_events, False)
