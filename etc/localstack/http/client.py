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


class SimpleRequestsClient(HttpClient):
    def request(self, request: Request) -> Response:
        """
        Very naive implementation to make the given HTTP request using the requests library, i.e., process the request
        as a client.

        TODO: over time, this should become more sophisticated, specifically the use of restore_payload should only be
         used only when necessary (when the stream has been consumed), and by default the underlying stream should be
         streamed to the destination.

        :param request: the request to perform
        :return: the response.
        """
        response = requests.request(
            method=request.method,
            url=request.url,
            params=request.args,
            headers=request.headers,
            data=restore_payload(request),
        )

        return Response(
            response=response.content,
            status=response.status_code,
            headers=Headers(dict(response.headers)),
        )


def make_request(request: Request) -> Response:
    """
    Convenience method to make the given HTTP as a client.

    :param request: the request to make
    :return: the response.
    """
    return SimpleRequestsClient().request(request)
