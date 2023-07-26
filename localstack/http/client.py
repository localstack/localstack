import abc
from urllib.parse import urlparse

import requests
from werkzeug import Request, Response
from werkzeug.datastructures import Headers

from localstack.http.request import (
    get_raw_base_url,
    get_raw_current_url,
    get_raw_path,
    restore_payload,
)


class HttpClient(abc.ABC):
    """
    An HTTP client that can make http requests using werkzeug's request object.
    """

    def request(self, request: Request, server: str | None = None) -> Response:
        """
        Make the given HTTP as a client.

        :param request: the request to make
        :param server: the URL to send the request to, which defaults to the host component of the original Request.
        :return: the response.
        """
        raise NotImplementedError

    def close(self):
        """
        Close any underlying resources the client may need.
        """
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _VerifyRespectingSession(requests.Session):
    """
    A class which wraps requests.Session to circumvent https://github.com/psf/requests/issues/3829.
    This ensures that if `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` are set, the request does not perform the TLS
    verification if `session.verify` is set to `False.
    """

    def merge_environment_settings(self, url, proxies, stream, verify, *args, **kwargs):
        if self.verify is False:
            verify = False

        return super(_VerifyRespectingSession, self).merge_environment_settings(
            url, proxies, stream, verify, *args, **kwargs
        )


class SimpleRequestsClient(HttpClient):
    session: requests.Session

    def __init__(self, session: requests.Session = None):
        self.session = session or _VerifyRespectingSession()

    @staticmethod
    def _get_destination_url(request: Request, server: str | None = None) -> str:
        if server:
            # accepts "http://localhost:5000" or "localhost:5000"
            if "://" in server:
                parts = urlparse(server)
                scheme, server = parts.scheme, parts.netloc
            else:
                scheme = request.scheme
            return get_raw_current_url(scheme, server, request.root_path, get_raw_path(request))

        return get_raw_base_url(request)

    def request(self, request: Request, server: str | None = None) -> Response:
        """
        Very naive implementation to make the given HTTP request using the requests library, i.e., process the request
        as a client.

        TODO: over time, this should become more sophisticated, specifically the use of restore_payload should only be
         used when necessary (when the underlying stream has been consumed), and by default the stream should be
         streamed to the destination.

        :param request: the request to perform
        :param server: the URL to send the request to, which defaults to the host component of the original Request.
        :return: the response.
        """

        url = self._get_destination_url(request, server)

        response = self.session.request(
            method=request.method,
            # use raw base url to preserve path url encoding
            url=url,
            # request.args are only the url parameters
            params=[(k, v) for k, v in request.args.items(multi=True)],
            headers=dict(request.headers.items()),
            data=restore_payload(request),
        )

        final_response = Response(
            response=response.content,
            status=response.status_code,
            headers=Headers(dict(response.headers)),
        )
        if request.method == "HEAD":
            # for HEAD  requests we have to keep the original content-length, but it will be re-calculated when creating
            # the final_response object
            final_response.content_length = response.headers.get("Content-Length", 0)
        return final_response

    def close(self):
        self.session.close()


class SimpleStreamingRequestsClient(SimpleRequestsClient):
    def request(self, request: Request, server: str | None = None) -> Response:
        """
        Very naive implementation to make the given HTTP request using the requests library, i.e., process the request
        as a client.

        :param request: the request to perform
        :param server: the URL to send the request to, which defaults to the host component of the original Request.
        :return: the response.
        """

        url = self._get_destination_url(request, server)

        response = self.session.request(
            method=request.method,
            # use raw base url to preserve path url encoding
            url=url,
            # request.args are only the url parameters
            params=[(k, v) for k, v in request.args.items(multi=True)],
            headers=dict(request.headers.items()),
            data=restore_payload(request),
            stream=True,
        )

        if request.method == "HEAD":
            # for HEAD  requests we have to keep the original content-length, but it will be re-calculated when creating
            # the final_response object
            final_response = Response(
                response=response.content,
                status=response.status_code,
                headers=Headers(dict(response.headers)),
            )
            final_response.content_length = response.headers.get("Content-Length", 0)
            return final_response

        response_headers = Headers(dict(response.headers))
        response_headers.pop("Content-Length", None)

        final_response = Response(
            response=(chunk for chunk in response.raw.stream(1024, decode_content=False)),
            status=response.status_code,
            headers=response_headers,
        )

        return final_response


def make_request(request: Request) -> Response:
    """
    Convenience method to make the given HTTP as a client.

    :param request: the request to make
    :return: the response.
    """
    with SimpleRequestsClient() as client:
        return client.request(request)
