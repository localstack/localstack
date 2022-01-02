from localstack.utils import http_utils


def test_add_query_params_to_url():

    tt = [
        {
            "uri": "http://localhost.localstack.cloud",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud?param=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud?foo=bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud?foo=bar&param" "=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud/foo/bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud/foo/bar?param" "=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud/foo/bar?foo=bar",
            "query_params": {"param": "122323"},
            "expected": "http://localhost.localstack.cloud/foo/bar?foo=bar" "&param=122323",
        },
        {
            "uri": "http://localhost.localstack.cloud?foo=bar",
            "query_params": {"foo": "bar"},
            "expected": "http://localhost.localstack.cloud?foo=bar",
        },
    ]

    for t in tt:
        result = http_utils.add_query_params_to_url(t["uri"], t["query_params"])
        assert result == t["expected"]
