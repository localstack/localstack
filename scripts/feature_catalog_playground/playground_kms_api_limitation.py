import importlib
import inspect
import json
import pkgutil

import localstack.feature_catalog.services as feature_catalog
from localstack.feature_catalog.service_feature import ApiCoverage, ServiceFeature
from localstack.feature_catalog.services import kms_api, kms_feature

# Automatically import all modules in the feature_catalog package
for _, module_name, _ in pkgutil.iter_modules(feature_catalog.__path__):
    importlib.import_module(f"{feature_catalog.__name__}.{module_name}")


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
import localstack.services.kms as kms_package

decorated_funcs = find_decorated_functions_in_package(kms_package, "")


def print_feature_limitations():
    for details in decorated_funcs:
        module = details.get("module")
        for feature in details.get("features"):
            feature_name = feature.get("feature")

            # Dynamically get the feature class from kms_feature.py
            feature_class = getattr(kms_feature, feature_name, None)

            # Get the limitations if the feature class exists
            if feature_class and issubclass(feature_class, ServiceFeature):
                limitations = getattr(feature_class, "limitations", [])
                limitations_str = ", ".join(limitations) if limitations else "No limitations"
            else:
                limitations_str = "No limitations"

            print(
                f"Function '{module}.{feature.get('name')}' is decorated with @{feature_name} \n"
                f"and has the following limitations: {limitations_str}\n"
            )

    # Now check for APIs decorated with @api_coverage (like in kms_api)
    for name, obj in inspect.getmembers(kms_api):
        if inspect.isclass(obj) and issubclass(obj, ApiCoverage) and obj != ApiCoverage:
            limitations = getattr(obj, "limitations", [])
            limitations_str = ", ".join(limitations) if limitations else "No limitations"
            print(f"API '{name}' has the following limitations: {limitations_str}\n")


print_feature_limitations()
