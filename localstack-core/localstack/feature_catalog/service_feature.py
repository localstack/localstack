from enum import Enum
from functools import wraps


class SupportStatus(Enum):
    SUPPORTED = 1
    SUPPORTED_MOCKED_ONLY = 2
    SUPPORTED_PARTIALLY_EMULATED = 3
    NOT_SUPPORTED = 4


class ImplementationStatus(Enum):
    FULLY_IMPLEMENTED = 1
    PARTIALLY_IMPLEMENTED = 2
    EXPERIMENTAL = 3


class ServiceFeature:
    implementation_status: ImplementationStatus

    def __init__(self, func):
        self.feature = self.__class__.__name__
        self.func = func
        wraps(func)(self)

    def __get__(self, instance, owner):
        """
        This makes the decorator work with bound methods inside classes.
        It is called when the method is accessed on an instance.
        """
        # Return a bound method by wrapping the function and passing the instance (`self`)
        if instance is None:
            return self  # Return the unbound function when accessed via the class
        # Bind the function to the instance by returning a wrapper
        return lambda *args, **kwargs: self(instance, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)
