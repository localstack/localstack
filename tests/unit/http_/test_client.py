import contextlib
import ssl

import certifi
import pytest
from pytest_httpserver import HTTPServer
from requests.exceptions import SSLError

from localstack.http import Request
from localstack.http.client import SimpleRequestsClient
from localstack.utils.ssl import create_ssl_cert


@pytest.fixture(scope="session")
def custom_httpserver_with_ssl():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _, cert_file_name, key_file_name = create_ssl_cert()
    context.load_cert_chain(cert_file_name, key_file_name)
    return context


@pytest.fixture(scope="session")
def make_ssl_httpserver(custom_httpserver_with_ssl):
    # we don't want to override SSL for every httpserver fixture
    # see https://pytest-httpserver.readthedocs.io/en/latest/fixtures.html#make-httpserver
    server = HTTPServer(ssl_context=custom_httpserver_with_ssl)
    server.start()
    yield server
    server.clear()
    if server.is_running():
        server.stop()


@pytest.fixture
def ssl_httpserver(make_ssl_httpserver):
    server = make_ssl_httpserver
    yield server
    server.clear()


@pytest.mark.parametrize("verify", [True, False])
@pytest.mark.parametrize("cert_env", [None, "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_http_clients_respect_verify(verify, cert_env, ssl_httpserver, monkeypatch):
    # If we want to test that a certain environment variable, setting the CA bundle, is set, we
    # just set the same path as requests uses anyway (the issues is caused just by the variables being set).
    if cert_env:
        monkeypatch.setenv(cert_env, certifi.where())

    client = SimpleRequestsClient()
    client.session.verify = verify

    # Configure the SSL http server fixture
    expected_response = {"Result": "This request has not been verified!"}
    ssl_httpserver.expect_request("/").respond_with_json(expected_response)
    request = Request(
        scheme="https",
    )

    # Test requests where the verification would fail:
    # Either expect an SSL error (if verify = True), or expect the request to be successful (i.e. not raise anything)
    context_manager = pytest.raises(SSLError) if verify else contextlib.suppress()
    with context_manager:
        # Send the request to the server's host, this is never in the SAN of the cert and fails when being verified
        response = client.request(
            request, server=f"{ssl_httpserver.host}:{ssl_httpserver.port}"
        ).json
        assert response == expected_response

    # Test requests where the verification is successful:
    # Send the request to "localhost.localstack.cloud", which is in the SAN and can be verified
    response = client.request(
        request, server=f"localhost.localstack.cloud:{ssl_httpserver.port}"
    ).json
    assert response == expected_response
