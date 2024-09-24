from json import JSONEncoder
from typing import Any, Type

from rolo import Response as RoloResponse

from localstack.utils.common import CustomEncoder


class Response(RoloResponse):
    """
    An HTTP Response object, which simply extends werkzeug's Response object with a few convenience methods.
    """

    def set_json(self, doc: Any, cls: Type[JSONEncoder] = CustomEncoder):
        """
        Serializes the given dictionary using localstack's ``CustomEncoder`` into a json response, and sets the
        mimetype automatically to ``application/json``.

        :param doc: the response dictionary to be serialized as JSON
        :param cls: the json encoder used
        """
        return super().set_json(doc, cls or CustomEncoder)
