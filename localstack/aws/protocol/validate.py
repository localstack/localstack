"""Slightly extends the ``botocore.validate`` package to provide better integration with our parser/serializer."""
from typing import Any, Dict, List, NamedTuple

from botocore.model import OperationModel, Shape
from botocore.validate import ParamValidator as BotocoreParamValidator
from botocore.validate import ValidationErrors as BotocoreValidationErrors
from botocore.validate import type_check

from localstack.aws.api import ServiceRequest


class Error(NamedTuple):
    """
    A wrapper around ``botocore.validate`` error tuples.

    Attributes:
        reason      The error type
        name        The name of the parameter the error occurred at
        attributes  Error type-specific attributes
    """

    reason: str
    name: str
    attributes: Dict[str, Any]


class ParameterValidationError(Exception):

    error: Error

    def __init__(self, error: Error) -> None:
        self.error = error
        super().__init__(self.message)

    @property
    def reason(self):
        return self.error.reason

    @property
    def message(self) -> str:
        """
        Returns a default message for the error formatted by BotocoreValidationErrors.
        :return: the exception message.
        """
        return BotocoreValidationErrors()._format_error(self.error)


class MissingRequiredField(ParameterValidationError):
    @property
    def required_name(self) -> str:
        return self.error.attributes["required_name"]


# TODO: extend subclasses with properties from error arguments as needed. see ValidationErrors._format_error for
#  which those are.


class UnknownField(ParameterValidationError):
    pass


class InvalidType(ParameterValidationError):
    pass


class InvalidRange(ParameterValidationError):
    pass


class InvalidLength(ParameterValidationError):
    pass


class JsonEncodingError(ParameterValidationError):
    pass


class InvalidDocumentType(ParameterValidationError):
    pass


class MoreThanOneInput(ParameterValidationError):
    pass


class EmptyInput(ParameterValidationError):
    pass


class ValidationErrors(BotocoreValidationErrors):
    def __init__(self, shape: Shape, params: Dict[str, Any]):
        super().__init__()
        self.shape = shape
        self.params = params
        self._exceptions: List[ParameterValidationError] = []

    @property
    def exceptions(self):
        return self._exceptions

    def raise_first(self):
        for error in self._exceptions:
            raise error

    def report(self, name, reason, **kwargs):
        error = Error(reason, name, kwargs)
        self._errors.append(error)
        self._exceptions.append(self.to_exception(error))

    def to_exception(self, error: Error) -> ParameterValidationError:
        error_type, name, additional = error

        if error_type == "missing required field":
            return MissingRequiredField(error)
        elif error_type == "unknown field":
            return UnknownField(error)
        elif error_type == "invalid type":
            return InvalidType(error)
        elif error_type == "invalid range":
            return InvalidRange(error)
        elif error_type == "invalid length":
            return InvalidLength(error)
        elif error_type == "unable to encode to json":
            return JsonEncodingError(error)
        elif error_type == "invalid type for document":
            return InvalidDocumentType(error)
        elif error_type == "more than one input":
            return MoreThanOneInput(error)
        elif error_type == "empty input":
            return EmptyInput(error)

        return ParameterValidationError(error)


class ParamValidator(BotocoreParamValidator):
    def validate(self, params: Dict[str, Any], shape: Shape):
        """Validate parameters against a shape model.

        This method will validate the parameters against a provided shape model.
        All errors will be collected before returning to the caller.  This means
        that this method will not stop at the first error, it will return all
        possible errors.

        :param params: User provided dict of parameters
        :param shape: A shape model describing the expected input.

        :return: A list of errors.

        """
        errors = ValidationErrors(shape, params)
        self._validate(params, shape, errors, name="")
        return errors

    @type_check(valid_types=(dict,))
    def _validate_structure(self, params, shape, errors, name):
        # our parser sets the value of required members to None if they are not in the incoming request. we correct
        # this behavior here to get the correct error messages.
        for required_member in shape.metadata.get("required", []):
            if required_member in params and params[required_member] is None:
                params.pop(required_member)

        super(ParamValidator, self)._validate_structure(params, shape, errors, name)


def validate_request(operation: OperationModel, request: ServiceRequest) -> ValidationErrors:
    """
    Validates the service request with the input shape of the given operation.

    :param operation: the operation
    :param request: the input shape of the operation being validated
    :return: ValidationError object
    """
    return ParamValidator().validate(request, operation.input_shape)
