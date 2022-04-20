import wsgiref.validate

import pytest
from werkzeug.exceptions import BadRequest

from localstack.http.request import Request, dummy_wsgi_environment


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

    with pytest.raises(BadRequest):
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


def test_args():
    r = Request("GET", "/", query_string="foo=420&bar=69")
    assert len(r.args) == 2
    assert r.args["foo"] == "420"
    assert r.args["bar"] == "69"


def test_values():
    r = Request("GET", "/", query_string="foo=420&bar=69")
    assert len(r.values) == 2
    assert r.values["foo"] == "420"
    assert r.values["bar"] == "69"


def test_form_empty():
    r = Request("POST", "/")
    assert len(r.form) == 0


def test_post_form_urlencoded_and_query():
    # see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST#example
    r = Request(
        "POST",
        "/form",
        query_string="query1=foo&query2=bar",
        body=b"field1=value1&field2=value2",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert len(r.form) == 2
    assert r.form["field1"] == "value1"
    assert r.form["field2"] == "value2"

    assert len(r.args) == 2
    assert r.args["query1"] == "foo"
    assert r.args["query2"] == "bar"

    assert len(r.values) == 4
    assert r.values["field1"] == "value1"
    assert r.values["field2"] == "value2"
    assert r.args["query1"] == "foo"
    assert r.args["query2"] == "bar"


def test_validate_dummy_environment():
    def validate(*args, **kwargs):
        assert wsgiref.validate.check_environ(dummy_wsgi_environment(*args, **kwargs)) is None

    validate(path="/foo/bar", body="foo")
    validate(path="/foo/bar", query_string="foo=420&bar=69")
    validate(server=("localstack.cloud", 4566))
    validate(server=("localstack.cloud", None))
    validate(remote_addr="127.0.0.1")
    validate(headers={"Content-Type": "text/xml"}, body=b"")
