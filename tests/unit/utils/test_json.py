import json

from localstack.utils.json import BytesEncoder, assign_to_path


def test_json_encoder():
    payload = {"foo": b"foobar"}
    result = json.dumps(payload, cls=BytesEncoder)
    assert result == '{"foo": "Zm9vYmFy"}'


def test_assign_to_path_single_path():
    target = {}
    assign_to_path(target, "a", "bar")
    assert target == {"a": "bar"}


def test_assign_multi_nested_path():
    target = {}
    assign_to_path(target, "a.b.foo", "bar")
    assert target == {"a": {"b": {"foo": "bar"}}}


def test_assign_to_path_mixed_delimiters():
    target = {}
    assign_to_path(target, "a.b/c", "d", delimiter="/")
    assert target == {"a.b": {"c": "d"}}
