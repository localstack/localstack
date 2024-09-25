import importlib
import inspect
import json
import pkgutil

import localstack.services.cloudwatch.feature_catalog as cloudwatch_features
from localstack.feature_catalog.service_feature import ServiceFeature

# Automatically import all modules in the feature_catalog package
for _, module_name, _ in pkgutil.iter_modules(cloudwatch_features.__path__):
    importlib.import_module(f"{cloudwatch_features.__name__}.{module_name}")


def get_class_hierarchy(cls, level=0):
    indent = " " * (level * 4)  # Indentation to reflect the level in the hierarchy
    print(f"{indent}{cls.__name__}")  # Print the current class name
    for subclass in cls.__subclasses__():
        get_class_hierarchy(subclass, level + 1)  # Recursively get the hierarchy of subclasses


def get_class_hierarchy_dict(cls):
    hierarchy = {cls.__name__: []}  # Dictionary with class name as key and subclasses as list
    for subclass in cls.__subclasses__():
        hierarchy[cls.__name__].append(get_class_hierarchy_dict(subclass))  # Recursive call
    return hierarchy


print(json.dumps(get_class_hierarchy_dict(ServiceFeature), indent=2))


def find_decorated_functions_and_methods(module, decorator_attr):
    decorated_functions = []

    # Search all members of the module
    for name, obj in inspect.getmembers(module):
        # If it's a function (not inside a class)
        if feature := getattr(obj, "feature", None):
            decorated_functions.append({"name": name, "feature": feature})

        # If it's a class, check its methods
        elif inspect.isclass(obj):
            for method_name, method in inspect.getmembers(obj):
                if feature := getattr(method, "feature", None):
                    decorated_functions.append(
                        {"name": f"{name}.{method_name}", "feature": feature}
                    )

    return decorated_functions


def find_decorated_functions_in_package(package, decorator_attr):
    decorated_functions = []

    # Iterate through all modules in the package
    for module_info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_info.name}")

        # Find decorated functions and methods within the module
        features = find_decorated_functions_and_methods(module, decorator_attr)
        if features:
            decorated_functions.append({"module": module.__name__, "features": features})

    return decorated_functions


# Usage: Find all decorated functions in the entire cloudwatch package
import localstack.services.cloudwatch as cloudwatch_package

decorated_funcs = find_decorated_functions_in_package(cloudwatch_package, "is_decorated_by_alarm")

for details in decorated_funcs:
    module = details.get("module")
    for feature in details.get("features"):
        print(
            f"Function '{module}.{feature.get('name')}' is decorated with @{feature.get('feature')}"
        )


# def find_decorators_in_function(func):
#     """Return a list of decorators applied to the given function."""
#     decorators = []
#
#     # Check if the function has attributes for known decorators
#     if feature := getattr(func, "feature", None):
#         decorators.append(feature)
#
#     # You can check for additional decorators here
#
#     return decorators
#
#
# def find_all_decorators(module):
#     """Find all decorators applied to functions and methods in the given module."""
#     all_decorators = {}
#
#     # Loop through all members of the module
#     for name, obj in inspect.getmembers(module):
#         # If it's a function (not inside a class)
#         if isinstance(obj, types.FunctionType):
#             decorators = find_decorators_in_function(obj)
#             if decorators:
#                 all_decorators[name] = decorators
#
#         # If it's a class, check its methods
#         if inspect.isclass(obj):
#             for method_name, method in inspect.getmembers(obj, predicate=inspect.isfunction):
#                 decorators = find_decorators_in_function(method)
#                 if decorators:
#                     all_decorators[f"{obj.__name__}.{method_name}"] = decorators
#
#     return all_decorators
#
#
# # Example usage
# decorators_found = find_all_decorators(cloudwatch_package)
#
# for func_name, decorators in decorators_found.items():
#     print(f"Function '{func_name}' has decorators: {', '.join(decorators)}")
