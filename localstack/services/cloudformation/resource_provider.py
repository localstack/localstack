from dataclasses import dataclass
from typing import Generic, TypeVar

Properties = TypeVar("Properties")


@dataclass
class ProgressEvent(Generic[Properties]):
    pass


class ResourceProvider(Generic[Properties]):
    def create(self, *args, **kwargs) -> ProgressEvent[Properties]:
        raise NotImplementedError
