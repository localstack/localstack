from json import JSONEncoder
from typing import Type

from rolo.routing.handler import Handler, ResultValue
from rolo.routing.handler import handler_dispatcher as _handler_dispatcher
from rolo.routing.router import Dispatcher

from localstack.utils.json import CustomEncoder

__all__ = [
    "ResultValue",
    "Handler",
    "handler_dispatcher",
]


def handler_dispatcher(json_encoder: Type[JSONEncoder] = None) -> Dispatcher[Handler]:
    """
    Replacement for ``rolo.dispatcher.handler_dispatcher`` that uses by default LocalStack's CustomEncoder for
    serializing JSON documents.

    :param json_encoder: the encoder to use
    :return: a Dispatcher that dispatches to instances of a Handler
    """
    return _handler_dispatcher(json_encoder or CustomEncoder)
