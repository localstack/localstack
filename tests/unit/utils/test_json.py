import json

from localstack.utils.json import BytesEncoder


def test_json_encoder():
    payload = {"foo": b"foobar"}
    result = json.dumps(payload, cls=BytesEncoder)
    assert result == '{"foo": "Zm9vYmFy"}'
