from localstack.services.logs.provider import get_pattern_matcher


class TestCloudWatchLogs:
    def test_get_pattern_matcher(self):
        def assert_match(filter_pattern, log_event, expected):
            matches = get_pattern_matcher(filter_pattern)
            assert matches(filter_pattern, log_event) == expected

        # expect to always be True until proper filter methods are available
        assert_match('{$.message = "Failed"}', {"message": '{"message":"Failed"}'}, True)
        assert_match("ERROR", {"message": "Failed"}, True)
        assert_match("", {"message": "FooBar"}, True)
        assert_match("[w1=Failed]", {"message": "Failed"}, True)
