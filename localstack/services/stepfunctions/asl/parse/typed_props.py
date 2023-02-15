from collections import OrderedDict
from typing import Any, Optional


class TypedProps:
    def __init__(self):
        self._instance_by_type: dict[type, Any] = OrderedDict()

    def add(self, instance: Any) -> None:
        self._add(type(instance), instance)

    def _add(self, typ: type, instance: Any) -> None:
        if instance is None:
            return
        if typ in self._instance_by_type:
            raise ValueError(
                f"Redefinition of type '{typ}', from '{self._instance_by_type[typ]}' to '{instance}'."
            )
        self._instance_by_type[typ] = instance

    def get(self, typ: type, raise_on_missing: Optional[Exception] = None) -> Optional[Any]:
        if raise_on_missing and typ not in self._instance_by_type:
            raise raise_on_missing
        return self._instance_by_type.get(typ)

    def __repr__(self):
        return str(self._instance_by_type)

    def __str__(self):
        return repr(self)
