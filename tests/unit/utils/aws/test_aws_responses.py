from localstack.utils.aws.aws_responses import parse_query_string

result_raw = {
    "DescribeChangeSetResult": {
        # ...
        "Changes": [
            {
                "ResourceChange": {
                    "Replacement": False,
                    "Scope": ["Tags"],
                },
                "Type": "Resource",
            }
        ]
    }
}

result_raw_none_element = {"a": {"b": None}}

result_raw_empty_list = {"a": {"b": []}}
result_raw_multiple_members = {"a": {"b": ["c", "d"]}}


class SomeClass:
    pass


result_raw_class_value = {"a": {"b": SomeClass()}}
multiple_root = {"a": "b", "c": "d"}
empty_dict = {}


def test_parse_query_string():
    assert parse_query_string("") == {}
    assert parse_query_string("?a=1") == {"a": "1"}
    assert parse_query_string("?a=1&b=foo2") == {"a": "1", "b": "foo2"}

    assert parse_query_string("http://example.com") == {}
    assert parse_query_string("http://example.com/foo/bar") == {}
    assert parse_query_string("http://example.com/foo/bar#test") == {}
    assert parse_query_string("http://example.com/foo/bar?a=1") == {"a": "1"}
    assert parse_query_string("http://example.com/foo/bar?foo=1&1=2") == {"foo": "1", "1": "2"}
    assert parse_query_string(
        "http://example.com/foo/bar?foo=1&redirect=http://test.com/redirect"
    ) == {
        "foo": "1",
        "redirect": "http://test.com/redirect",
    }
    assert parse_query_string(
        "http://example.com/foo/bar?foo=1&redirect=http%3A%2F%2Flocalhost%3A3001%2Fredirect"
    ) == {"foo": "1", "redirect": "http://localhost:3001/redirect"}
    assert parse_query_string("http://example.com/foo/bar?foo=1&1=2") == {"foo": "1", "1": "2"}

    assert parse_query_string("?foo=1&foo=2&", multi_values=True) == {"foo": ["1", "2"]}
    assert parse_query_string("?a=1&a=2&b=0&a=3", multi_values=True) == {
        "a": ["1", "2", "3"],
        "b": ["0"],
    }
    assert parse_query_string("ws://example.com/foo/bar?foo=1&1=2") == {"foo": "1", "1": "2"}
    assert parse_query_string("ws://example.com/foo/bar") == {}
    assert parse_query_string("wss://example.com/foo/bar?foo=1&1=2") == {"foo": "1", "1": "2"}
    assert parse_query_string("wss://example.com/foo/bar") == {}
    assert parse_query_string("https://example.com/foo/bar?foo=1&1=2") == {"foo": "1", "1": "2"}
    assert parse_query_string("https://example.com/foo/bar") == {}
