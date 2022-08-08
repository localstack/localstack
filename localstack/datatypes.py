from typing import TypeVar

from moto.core import BaseBackend

BaseStoreType = TypeVar("BaseStoreType", bound="BaseStore")  # noqa
"""Type annotation for any subclass of LocalStack BaseStore class."""

BaseBackendType = TypeVar("BaseBackendType", bound=BaseBackend)
"""Type annotation for any subclass of Moto BaseBackend class."""
