import json
from typing import Dict

from werkzeug.wrappers import Response as WerkzeugResponse

from localstack.utils.common import CustomEncoder


class Response(WerkzeugResponse):
    """
    An HTTP Response object.
    """

    def update_from(self, other: WerkzeugResponse):
        self.status_code = other.status_code
        self.response = other.response
        self.headers.update(other.headers)

    def set_json(self, doc: Dict):
        self.data = json.dumps(doc, cls=CustomEncoder)
        self.mimetype = "application/json"

    def set_response(self, response):
        if response is None:
            self.response = []
        elif isinstance(response, (str, bytes, bytearray)):
            self.data = response
        else:
            self.response = response

    def to_readonly_response_dict(self) -> Dict:
        """
        Returns a read-only version of a response dictionary as it is often expected by other libraries like boto.
        """
        return {
            "body": self.get_data(as_text=True).encode("utf-8"),
            "status_code": self.status_code,
            "headers": dict(self.headers),
        }
