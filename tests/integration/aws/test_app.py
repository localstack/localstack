import pytest
import requests
from werkzeug.exceptions import Forbidden

from localstack.config import get_edge_url
from localstack.services.edge import ROUTER


class TestExceptionHandlers:
    def test_internal_failure_handler_http_errors(self):
        response = requests.delete(get_edge_url() + "/_localstack/health")
        assert response.status_code == 405
        assert response.json() == {
            "error": "Method Not Allowed",
            "message": "The method is not allowed for the requested URL.",
        }
        assert "Allow" in response.headers

    @pytest.mark.xfail(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_http_errors(self, cleanups):
        def _raise_error(_request):
            raise Forbidden()

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 403
        assert response.json() == {
            "error": "Forbidden",
            "message": "You don't have the permission to access the requested resource. It is "
            "either read-protected or not readable by the server.",
        }

    def test_router_handler_patch_http_errors(self, cleanups):
        # this one works because PATCH operations are not detected by the service name parser as s3 requestss
        def _raise_error(_request):
            raise Forbidden()

        rule = ROUTER.add("/_raise_error", _raise_error, methods=["PATCH"])
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.patch(get_edge_url() + "/_raise_error")
        assert response.status_code == 403
        assert response.json() == {
            "error": "Forbidden",
            "message": "You don't have the permission to access the requested resource. It is "
            "either read-protected or not readable by the server.",
        }

    @pytest.mark.xfail(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_unexpected_errors(self, cleanups):
        def _raise_error(_request):
            raise ValueError("oh noes (this is expected)")

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 500
        assert response.json() == {
            "error": "Unexpected exception",
            "message": "oh noes (this is expected)",
            "type": "ValueError",
        }

    def test_404_unfortunately_detected_as_s3_request(self):
        # FIXME: this is because unknown routes have to be interpreted as s3 requests
        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 404
        assert "<Error><Code>NoSuchBucket</Code>" in response.text
