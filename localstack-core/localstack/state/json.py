from typing import IO, Any, Callable, Type, TypeVar

import jsonpickle
from jsonpickle.handlers import BaseHandler

from localstack.state import Decoder, Encoder

T = TypeVar("T", bound=BaseHandler)


def jsonpickle_register(cls: Type = None) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to register a custom handler for jsonpickle serialization.
    It provides a clean way to register custom jsonpickle handlers.

    :param cls: the type to register the handler for
    :raise ValueError: if the handler class does not extend handlers.BaseHandler
    :return:

    Example::

        @jsonpickle_register(MyObject)
        class MyObjectHandler(handlers.BaseHandler):
            def flatten(self, obj: MyObject, data: dict) -> dict:
                # ...
                return data

            def restore(self, data: dict) -> MyObject:
                # ...
                return MyObject(...)
    """

    def _wrapper(handler_class):
        if not issubclass(handler_class, BaseHandler):
            raise ValueError(f"Cannot register {handler_class}")

        jsonpickle.handlers.register(cls, handler_class)
        return handler_class

    return _wrapper


class JsonEncoder(Encoder):
    """
    An Encoder that uses ``jsonpickle`` under the hood.
    """

    def __init__(self, pickler_class: Type[jsonpickle.Pickler] = None):
        self.pickler_class = pickler_class or jsonpickle.Pickler()

    def encode(self, obj: Any, file: IO[bytes]):
        json_str = jsonpickle.encode(obj, context=self.pickler_class)
        file.write(json_str.encode("utf-8"))


class JsonDecoder(Decoder):
    """
    A Decoder that uses ``jsonpickle`` under the hood.
    """

    unpickler_class: Type[jsonpickle.Unpickler]

    def __init__(self, unpickler_class: Type[jsonpickle.Unpickler] = None):
        self.unpickler_class = unpickler_class or jsonpickle.Unpickler()

    def decode(self, file: IO[bytes]) -> Any:
        json_str = file.read().decode("utf-8")
        return jsonpickle.decode(json_str, context=self.unpickler_class)
