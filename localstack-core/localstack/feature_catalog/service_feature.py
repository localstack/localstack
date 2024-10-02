from enum import Enum
from functools import wraps


class SupportStatus(Enum):
    """
    Indicates the support on LocalStack in regard to the actual implementation
    E.g.
    SUPPORTED means that everything is behaving as on AWS
    SUPPORTED_MOCKED_ONLY means that the response is the same as on AWS, but there is no actual behavior behind it (e.g. no database created)
    SUPPORTED_PARTIALLY_EMULATED means that there is some kind of emulation, but there may be parts missing
    NOT_SUPPORTED means this is not implemented at all on LS
    """

    SUPPORTED = 1
    SUPPORTED_MOCKED_ONLY = 2
    SUPPORTED_PARTIALLY_EMULATED = 3
    NOT_SUPPORTED = 4


class ImplementationStatus(Enum):
    """
    Indicates implementation status on LS
    E.g.
    FULLY_IMPLEMENTED means that all (important?) operations are implemented
    PARTIALLY_IMPLEMENTED means some selected operations are implemented
    EXPERIMENTAL means that there is some implementation, but this feature is still higly experimental
    """

    FULLY_IMPLEMENTED = 1
    PARTIALLY_IMPLEMENTED = 2
    EXPERIMENTAL = 3


class ServiceFeature:
    """
    The base class for all service features
    For each service there should be separate file in ./services that defines further features and sub features
    The concrete features (or sub features) can then be used as decorator for api-operations or functions

    With the script in scripts/feature_catalog_playground/playground.py we can create a first PoC that outputs the
    details of all ServiceFeature subclasses in a json-format, including attributes;
    also detecting all operations/functions that use the feature as decorator and map those accordingly
    """

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


class ApiCoverage:
    """
    One suggestions on how to track specific api-operation limitations:
    This is the base class for limitations that we want to track on an api-operation level, instead of a feature-level

    Alternative solution would be using the ApiLimitation (file api_limitation.py), which provides a more generic way
    of doing so
    """

    implementation_status: ImplementationStatus

    def __init__(self, func):
        self.func = func
        wraps(func)(self)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)
