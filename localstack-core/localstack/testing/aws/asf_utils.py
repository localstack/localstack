import importlib
import importlib.util
import inspect
import pkgutil
import re
from types import FunctionType, ModuleType, NoneType, UnionType
from typing import Optional, Pattern, Union, get_args, get_origin


def _import_submodules(
    package_name: str, module_regex: Optional[Pattern] = None, recursive: bool = True
) -> dict[str, ModuleType]:
    """
    Imports all submodules of the given package with the defined (optional) module_suffix.

    :param package_name: To start the loading / importing at
    :param module_regex: Optional regex to filter the module names for
    :param recursive: True if the package should be loaded recursively
    :return:
    """
    package = importlib.import_module(package_name)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if not module_regex or module_regex.match(name):
            results[name] = importlib.import_module(name)
        if recursive and is_pkg:
            results.update(_import_submodules(name, module_regex, recursive))
    return results


def _collect_provider_classes(
    provider_module: str, provider_module_regex: Pattern, provider_class_regex: Pattern
) -> list[type]:
    """
    Collects all provider implementation classes which should be tested.
    :param provider_module: module to start collecting in
    :param provider_module_regex: Regex to filter the module names for
    :param provider_class_regex: Regex to filter the provider class names for
    :return: list of classes to check the operation signatures of
    """
    provider_classes = []
    provider_modules = _import_submodules(provider_module, provider_module_regex)
    # check that all these files don't import any encrypted code
    for _, mod in provider_modules.items():
        # get all classes of the module which end with "Provider"
        classes = [
            cls_obj
            for cls_name, cls_obj in inspect.getmembers(mod)
            if inspect.isclass(cls_obj) and provider_class_regex.match(cls_name)
        ]
        provider_classes.extend(classes)
    return provider_classes


def collect_implemented_provider_operations(
    provider_module: str = "localstack.services",
    provider_module_regex: Pattern = re.compile(r".*\.provider[A-Za-z_0-9]*$"),
    provider_class_regex: Pattern = re.compile(r".*Provider$"),
    asf_api_module: str = "localstack.aws.api",
) -> list[tuple[type, type, str]]:
    """
    Collects all implemented operations on all provider classes together with their base classes (generated API classes).
    :param provider_module: module to start collecting in
    :param provider_module_regex: Regex to filter the module names for
    :param provider_class_regex: Regex to filter the provider class names for
    :param asf_api_module: module which contains the generated ASF APIs
    :return: list of tuple, where each tuple is (provider_class: type, base_class: type, provider_function: str)
    """
    results = []
    provider_classes = _collect_provider_classes(
        provider_module, provider_module_regex, provider_class_regex
    )
    for provider_class in provider_classes:
        for base_class in provider_class.__bases__:
            base_parent_module = ".".join(base_class.__module__.split(".")[:-1])
            if base_parent_module == asf_api_module:
                # find all functions on the provider class which are also defined in the super class and are not dunder functions
                provider_functions = [
                    method
                    for method in dir(provider_class)
                    if hasattr(base_class, method)
                    and isinstance(getattr(base_class, method), FunctionType)
                    and method.startswith("__") is False
                ]
                for provider_function in provider_functions:
                    results.append((provider_class, base_class, provider_function))
    return results


def check_provider_signature(sub_class: type, base_class: type, method_name: str) -> None:
    """
    Checks if the signature of a given provider method is equal to the signature of the function with the same name on the base class.

    :param sub_class: provider class to check the given method's signature of
    :param base_class: API class to check the given method's signature against
    :param method_name: name of the method on the sub_class and base_class to compare
    :raise: AssertionError if the two signatures are not equal
    """
    try:
        sub_function = getattr(sub_class, method_name)
    except AttributeError:
        raise AttributeError(
            f"Given method name ('{method_name}') is not a method of the sub class ('{sub_class.__name__}')."
        )

    if not isinstance(sub_function, FunctionType):
        raise AttributeError(
            f"Given method name ('{method_name}') is not a method of the sub class ('{sub_class.__name__}')."
        )

    if not getattr(sub_function, "expand_parameters", True):
        # if the operation on the subclass has the "expand_parameters" attribute (it has a handler decorator) set to False, we don't care
        return

    if wrapped := getattr(sub_function, "__wrapped__", False):
        # if the operation on the subclass has a decorator, unwrap it
        sub_function = wrapped

    try:
        base_function = getattr(base_class, method_name)
        # unwrap from the handler decorator
        base_function = base_function.__wrapped__

        sub_spec = inspect.getfullargspec(sub_function)
        base_spec = inspect.getfullargspec(base_function)

        error_msg = f"{sub_class.__name__}#{method_name} breaks with {base_class.__name__}#{method_name}. This can also be caused by 'from __future__ import annotations' in a provider file!"

        # Assert that the signature is correct
        assert sub_spec.args == base_spec.args, error_msg
        assert sub_spec.varargs == base_spec.varargs, error_msg
        assert sub_spec.varkw == base_spec.varkw, error_msg
        assert sub_spec.defaults == base_spec.defaults, (
            error_msg + f"\n{sub_spec.defaults} != {base_spec.defaults}"
        )
        assert sub_spec.kwonlyargs == base_spec.kwonlyargs, error_msg
        assert sub_spec.kwonlydefaults == base_spec.kwonlydefaults, error_msg

        # Assert that the typing of the implementation is equal to the base
        for kwarg in sub_spec.annotations:
            if kwarg == "return":
                assert sub_spec.annotations[kwarg] == base_spec.annotations[kwarg]
            else:
                # The API currently marks everything as required, and optional args are configured as:
                #    arg: ArgType = None
                # which is obviously incorrect.
                # Implementations sometimes do this correctly:
                #    arg: ArgType | None = None
                # These should be considered equal, so until the API is fixed, we remove any Optionals
                # This also gives us the flexibility to correct the API without fixing all implementations at the same time
                sub_type = _remove_optional(sub_spec.annotations[kwarg])
                base_type = _remove_optional(base_spec.annotations[kwarg])
                assert sub_type == base_type, (
                    f"Types for {kwarg} are different - {sub_type} instead of {base_type}"
                )

    except AttributeError:
        # the function is not defined in the superclass
        pass


def _remove_optional(_type: type) -> list[type]:
    if get_origin(_type) in [Union, UnionType]:
        union_types = list(get_args(_type))
        try:
            union_types.remove(NoneType)
        except ValueError:
            # Union of some other kind, like 'str | int'
            pass
        return union_types
    return [_type]
