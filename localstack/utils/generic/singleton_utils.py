from typing import Dict, Type

from localstack.utils.common import get_all_subclasses


class SubtypesInstanceManager:
    """Simple instance manager base class that scans the subclasses of a base type for concrete named
    implementations, and lazily creates and returns (singleton) instances on demand."""

    _instances: Dict[str, "SubtypesInstanceManager"]

    @classmethod
    def get(cls, subtype_name: str, raise_if_missing: bool = True):
        instances = cls.instances()
        base_type = cls.get_base_type()
        if not instances:
            for clazz in get_all_subclasses(base_type):
                instances[clazz.impl_name()] = clazz()
        instance = instances.get(subtype_name)
        if not instance and raise_if_missing:
            raise NotImplementedError(
                f"Unable to find implementation named '{subtype_name}' for base type {base_type}"
            )
        return instance

    @classmethod
    def instances(cls) -> Dict[str, "SubtypesInstanceManager"]:
        base_type = cls.get_base_type()
        if not hasattr(base_type, "_instances"):
            base_type._instances = {}
        return base_type._instances

    @staticmethod
    def impl_name() -> str:
        """Name of this concrete subtype - to be implemented by subclasses."""
        raise NotImplementedError

    @classmethod
    def get_base_type(cls) -> Type:
        """Get the base class for which instances are being managed - can be customized by subtypes."""
        return cls
