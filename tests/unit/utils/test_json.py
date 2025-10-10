import json

from localstack.utils.json import BytesEncoder, assign_to_path


def test_json_encoder():
    payload = {"foo": b"foobar"}
    result = json.dumps(payload, cls=BytesEncoder)
    assert result == '{"foo": "Zm9vYmFy"}'


def test_assign_to_path_single_path():
    target = {}
    assign_to_path(target, "foo", "bar")
    assert target == {"foo": "bar"}
