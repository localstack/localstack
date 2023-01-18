import abc

import requests
from werkzeug import Request, Response
from werkzeug.datastructures import Headers

from localstack.http.request import restore_payload


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

    def __init__(self, session: requests.Session = None):
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
        response = self.session.request(
            method=request.method,
            url=request.base_url,
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


def make_request(request: Request) -> Response:
    """
    Convenience method to make the given HTTP as a client.

    :param request: the request to make
    :return: the response.
    """
    with SimpleRequestsClient() as client:
        return client.request(request)
