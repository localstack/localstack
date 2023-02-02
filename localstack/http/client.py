import abc

import requests
from werkzeug import Request, Response
from werkzeug.datastructures import Headers
from werkzeug.sansio.utils import get_current_url

from localstack.http.request import get_raw_base_url, get_raw_path, restore_payload


class HttpClient(abc.ABC):
    """
    An HTTP client that can make http requests using werkzeug's request object.
    """

    def request(self, request: Request) -> Response:
        """
        Make the given HTTP as a client.

        :param request: the request to make
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


class SimpleRequestsClient(HttpClient):
    session: requests.Session

    def __init__(self, session: requests.Session = None, prefer_server: bool = False):
        """
        :param session: to reuse (if given)
        :param prefer_server: True if the WSGI environment's SERVER_NAME and SERVER_PORT should have precedence over the
                                Request's "Host" header when determining the target URL. This allows setting a different
                                target without modifying the Host header.
        """
        self.prefer_server = prefer_server
        self.session = session or requests.Session()

    def request(self, request: Request) -> Response:
        """
        Very naive implementation to make the given HTTP request using the requests library, i.e., process the request
        as a client.

        TODO: over time, this should become more sophisticated, specifically the use of restore_payload should only be
         used when necessary (when the underlying stream has been consumed), and by default the stream should be
         streamed to the destination.

        :param request: the request to perform
        :return: the response.
        """
        url = self._get_url(request)
        response = self.session.request(
            method=request.method,
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

    def _get_url(self, request: Request):
        """
        Determines the target URL of the given request depending on the configuration of this client.

        :param request: to construct the URL for
        :return: URL string which can be used as the target URL by an HTTP client library
        """
        if self.prefer_server:
            # Prefer the WSGI `SERVER_*` fields instead of the `Host` header field
            server_tuple = request.server
            if server_tuple is not None and server_tuple[0] is not None:
                host_part = server_tuple[0]
                port_part = server_tuple[1]
                host = host_part if port_part is None else f"{host_part}:{port_part}"
                scheme = request.environ.get("SERVER_PROTOCOL", None) or request.scheme
                # make sure to use the raw path to avoid encoding issues
                return get_current_url(scheme, host, request.root_path, get_raw_path(request))
        # make sure to use the raw base URL to avoid encoding issues
        return get_raw_base_url(request)

    def close(self):
        self.session.close()


def make_request(request: Request) -> Response:
    """
    Convenience method to make the given HTTP as a client.

    :param request: the request to make
    :return: the response.
    """
    with SimpleRequestsClient() as client:
        return client.request(request)
