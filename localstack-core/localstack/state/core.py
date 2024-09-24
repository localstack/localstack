"""Core concepts of the persistence API."""

import io
import os
import pathlib
from typing import IO, Any, Protocol, runtime_checkable


class StateContainer(Protocol):
    """While a StateContainer can in principle be anything, localstack currently supports by default the following
    containers:

    - BackendDict (moto backend state)
    - AccountRegionBundle (localstack stores)
    - AssetDirectory (folders on disk)
    """

    service_name: str


class StateLifecycleHook:
    """
    There are three well-known state manipulation operations for a service provider:

    - reset: the state within the service provider is reset, stores cleared, directories removed
    - save: the state of the service provider is extracted and stored into some format (on disk, pods, ...)
    - load: the state is injected into the service, or state directories on disk are restored
    """

    def on_before_state_reset(self):
        """Hook triggered before the provider's state containers are reset/cleared."""
        pass

    def on_after_state_reset(self):
        """Hook triggered after the provider's state containers have been reset/cleared."""
        pass

    def on_before_state_save(self):
        """Hook triggered before the provider's state containers are saved."""
        pass

    def on_after_state_save(self):
        """Hook triggered after the provider's state containers have been saved."""
        pass

    def on_before_state_load(self):
        """Hook triggered before a previously serialized state is loaded into the provider's state containers."""
        pass

    def on_after_state_load(self):
        """Hook triggered after a previously serialized state has been loaded into the provider's state containers."""
        pass


class StateVisitor:
    def visit(self, state_container: StateContainer):
        """
        Visit (=do something with) a given state container. A state container can be anything that holds service state.
        An AccountRegionBundle, a moto BackendDict, or a directory containing assets.
        """
        raise NotImplementedError


@runtime_checkable
class StateVisitable(Protocol):
    def accept_state_visitor(self, visitor: StateVisitor):
        """
        Accept a StateVisitor. The implementing method should call visit not necessarily on itself, but can also call
        the visit method on the state container it holds. The common case is calling visit on the stores of a provider.
        :param visitor: the StateVisitor
        """


class AssetDirectory:
    """
    A state container manifested as a directory on the file system.
    """

    service_name: str
    path: pathlib.Path

    def __init__(self, service_name: str, path: str | os.PathLike):
        if not service_name:
            raise ValueError("service name must be set")

        if not path:
            raise ValueError("path must be set")

        if not isinstance(path, os.PathLike):
            path = pathlib.Path(path)

        self.service_name = service_name
        self.path = path

    def __str__(self) -> str:
        return str(self.path)


class Encoder:
    def encodes(self, obj: Any) -> bytes:
        """
        Encode an object into bytes.

        :param obj: the object to encode
        :return: the encoded object
        """
        b = io.BytesIO()
        self.encode(obj, b)
        return b.getvalue()

    def encode(self, obj: Any, file: IO[bytes]):
        """
        Encode an object into bytes.

        :param obj: the object to encode
        :param file: the file to write the encoded data into
        """
        raise NotImplementedError


class Decoder:
    def decodes(self, data: bytes) -> Any:
        """
        Decode a previously encoded object.

        :param data: the encoded object to decode
        :return: the decoded object
        """
        return self.decode(io.BytesIO(data))

    def decode(self, file: IO[bytes]) -> Any:
        """
        Decode a previously encoded object.

        :param file: the io object containing the object to decode
        :return: the decoded object
        """
        raise NotImplementedError
