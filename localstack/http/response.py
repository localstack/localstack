import json
from typing import Any, Dict, Iterable, Union

from werkzeug.wrappers import Response as WerkzeugResponse

from localstack.utils.common import CustomEncoder


class Response(WerkzeugResponse):
    """
    An HTTP Response object, which simply extends werkzeug's Response object with a few convenience methods.
    """

    def update_from(self, other: WerkzeugResponse):
        """
        Updates this response object with the data from the given response object. It reads the status code,
        the response data, and updates its own headers (overwrites existing headers, but does not remove ones not
        present in the given object).

        :param other: the response object to read from
        """
        self.status_code = other.status_code
        self.response = other.response
        self.headers.update(other.headers)

    def set_json(self, doc: Any):
        """
        Serializes the given dictionary using localstack's ``CustomEncoder`` into a json response, and sets the
        mimetype automatically to ``application/json``.

        :param doc: the response dictionary to be serialized as JSON
        """
        self.data = json.dumps(doc, cls=CustomEncoder)
        self.mimetype = "application/json"

    def set_response(self, response: Union[str, bytes, bytearray, Iterable[bytes]]):
        """
        Function to set the low-level ``response`` object. This is copied from the werkzeug Response constructor. The
        response attribute always holds an iterable of bytes. Passing a str, bytes or bytearray is equivalent to
        calling ``response.data = <response>``. If None is passed, then it will create an empty list. If anything
        else is passed, the value is set directly. This value can be a list of bytes, and iterator that returns bytes
        (e.g., a generator), which can be used by the underlying server to stream responses to the client. Anything else
        (like passing dicts) will result in errors at lower levels of the server.

        :param response: the response value
        """
        if response is None:
            self.response = []
        elif isinstance(response, (str, bytes, bytearray)):
            self.data = response
        else:
            self.response = response

        return self

    def to_readonly_response_dict(self) -> Dict:
        """
        Returns a read-only version of a response dictionary as it is often expected by other libraries like boto.
        """
        return {
            "body": self.stream if self.is_streamed else self.data,
            "status_code": self.status_code,
            "headers": dict(self.headers),
        }

    @classmethod
    def for_json(cls, doc: Any, *args, **kwargs) -> "Response":
        """
        Creates a new JSON response from the given document. It automatically sets the mimetype to ``application/json``.

        :param doc: the document to serialize into JSON
        :param args: arguments passed to the ``Response`` constructor
        :param kwargs: keyword arguments passed to the ``Response`` constructor
        :return: a new Response object
        """
        response = cls(*args, **kwargs)
        response.set_json(doc)
        return response
