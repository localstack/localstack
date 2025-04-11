import functools
from contextlib import contextmanager
from typing import Callable, TypeVar

from botocore.client import BaseClient

T = TypeVar("T")

Transformer = Callable[[T | None], T | None]
Validator = Callable[[T], bool]


def _handle_parameter(
    parameter_key: str,
    header_key: str,
    validation_fns: list[Validator] | None = None,
    transformation_fns: list[Transformer] | None = None,
):
    def convert_parameter_to_header(params, context, **kwargs):
        parameter_value = params.pop(parameter_key, None)
        if not parameter_value:
            return

        if validation_fns and not all(validate(parameter_value) for validate in validation_fns):
            return

        if transformation_fns:
            parameter_value = functools.reduce(
                lambda x, y: y(x), transformation_fns, parameter_value
            )

            if not parameter_value:
                return

        context[header_key] = str(parameter_value)

    return convert_parameter_to_header


def _handle_inject_headers(header_key: str):
    def inject_header(params, context, **kwargs):
        if header_value := context.pop(header_key, None):
            params["headers"][header_key] = header_value

    return inject_header


@contextmanager
def register_parameter_to_header_hooks(client: BaseClient):
    """
    Register event hooks against a client's boto operations that converts certain parameters to HTTP headers.

    Args:
    client: The boto client to register hooks on

    Yields:
    Function to register parameter-to-header transformations with signature:
        register(
            operation: str,           # Operation name
            parameter: str,           # Parameter to convert
            header: str,              # Header to create
            validators: list = None,  # Optional validation functions
            transformers: list = None # Optional transformation functions
        )

    Example basic:
    >>> with register_parameter_to_header_hooks(s3_client) as register:
    >>>     register('PutObject', 'trace_id', 'X-Trace-ID')

    Example validator, that will only register if `priority > 10`:
    >>> with register_parameter_to_header_hooks(sqs_client) as register:
    >>>     register('SendMessage', 'priority', 'X-Priority',
    >>>              validators=[lambda x: x > 10])
    """
    handlers: list[tuple] = []

    # Extract the service name (i.e sqs, s3) from the client
    service = client.meta.service_model.service_id.hyphenize()

    valid_operation_names = client.meta.service_model.operation_names

    def _register_parameter_to_header_hook(
        operation: str,
        parameter: str,
        header: str,
        validators: list[Validator] | None = None,
        transformers: list[Transformer] | None = None,
    ):
        if operation not in valid_operation_names:
            raise ValueError(
                f"operation {operation} is not valid for service {service}. Valid operations are: {valid_operation_names}"
            )

        handlers.append(
            (
                operation,
                _handle_parameter(
                    parameter_key=parameter,
                    header_key=header,
                    validation_fns=validators,
                    transformation_fns=transformers,
                ),
                _handle_inject_headers(header_key=header),
            )
        )

    try:
        yield _register_parameter_to_header_hook
    except Exception:
        handlers.clear()
        raise
    finally:
        event_system = client.meta.events
        for operation, param_fn, inject_fn in handlers:
            # TODO: Unsure how to handle invalid service/operation
            event_system.register(f"provide-client-params.{service}.{operation}", param_fn)
            event_system.register(f"before-call.{service}.{operation}", inject_fn)
