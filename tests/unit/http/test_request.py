from json import JSONDecodeError

import pytest

from localstack.http.request import Request


def test_get_json():
    r = Request(
        "POST",
        "/",
        headers={"Content-Type": "application/json"},
        body=b'{"foo": "bar", "baz": 420}',
    )
    assert r.json == {"foo": "bar", "baz": 420}


def test_get_json_force():
    r = Request("POST", "/", body=b'{"foo": "bar", "baz": 420}')
    assert r.get_json(force=True) == {"foo": "bar", "baz": 420}


def test_get_json_invalid():
    r = Request("POST", "/", body=b'{"foo": "')

    with pytest.raises(JSONDecodeError):
        assert r.get_json(force=True)

    assert r.get_json(force=True, silent=True) is None


def test_get_data():
    r = Request("GET", "/", body="foobar")
    assert r.data == b"foobar"


def test_get_data_as_text():
    r = Request("GET", "/", body="foobar")
    assert r.get_data(as_text=True) == "foobar"


def test_get_stream():
    r = Request("GET", "/", body=b"foobar")
    assert r.stream.read(3) == b"foo"
    assert r.stream.read(3) == b"bar"
