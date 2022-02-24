from localstack.utils.http import ACCEPT, add_query_params_to_url, canonicalize_headers


def test_canonicalize_headers():
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9," "*/*;q=0.8",
        "Accept-encoding": "gzip, deflate, br",
        "Accept-language": "en-GB,en;q=0.9",
        "Host": "c2m48evwfk.execute-api.eu-west-1.amazonaws.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 "
        "Safari/605.1.15",
        "X-Amzn-Trace-Id": "Root=1-61d0de53-5843d28d07bf39f63b105411",
        "X-Forwarded-For": "37.228.224.133",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https",
    }
    canonicals_headers = canonicalize_headers(headers)
    result_headers = {
        k: v for k, v in canonicals_headers.items() if not k.lower().startswith(ACCEPT)
    }
    expected_headers = {k: v for k, v in headers.items() if not k.lower().startswith(ACCEPT)}

    assert result_headers == expected_headers


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
        result = add_query_params_to_url(t["uri"], t["query_params"])
        assert result == t["expected"]
