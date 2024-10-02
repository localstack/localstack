"""
This is a PoC script that will create a json-output from the features defined in `localstack/feature_catalog/services`
In order to get additional information, e.g., which functions use these as decorators, the script also iterates through
(currently only considering selected) services-packages, and collects the function names.

At the end we are able to provide a mapping, e.g., functions and api-operation-names that belong to a specific feature.

In the following example, the attributes for "operations" and "api-limitations" are dynamically collected,
depending on the used decorators:

{
  "ServiceFeature": {
    "CloudWatchFeature": {
      "docs": {
        "implementation_status": "ImplementationStatus.PARTIALLY_IMPLEMENTED"
      },
      ....
      "Alarm": {
        "docs": {
          "general_docs": "Alarms are used to set thresholds for metrics and trigger actions",
          "supported": "SupportStatus.SUPPORTED_PARTIALLY_EMULATED",
          "implementation_status": "ImplementationStatus.PARTIALLY_IMPLEMENTED",
          "aws_docs_link": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
        },
        "CompositeAlarm": {
          "docs": {
            "supported": "SupportStatus.SUPPORTED_MOCKED_ONLY",
            "aws_docs_link": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html"
          },
          "operations": [
            "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.put_composite_alarm"
          ]
        },
        "MetricAlarm": {
          "docs": {
            "supported": "SupportStatus.SUPPORTED",
            "supported_triggers": [
              "SNS",
              "Lambda"
            ]
          },
          "operations": [
            "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.put_metric_alarm"
          ]
        },
        "operations": [
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.delete_alarms",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.describe_alarm_history",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.describe_alarms",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.describe_alarms_for_metric",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.disable_alarm_actions",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.enable_alarm_actions",
          "localstack.services.cloudwatch.provider_v2.CloudwatchProvider.set_alarm_state",
          "localstack.services.cloudwatch.provider_v2.delete_alarms_helper"
        ]
      }
    },
    "KMSFeature": {
      "docs": {
        "implementation_status": "ImplementationStatus.PARTIALLY_IMPLEMENTED"
      },
        "Provisioning": {
          "docs": {
            "general_docs": "Manage the creation and modification of the keys.",
            "implementation_status": "ImplementationStatus.FULLY_IMPLEMENTED",
            "support_type": "SupportStatus.SUPPORTED",
            "aws_docs_link": "https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html",
            "api_operations": [
              "CreateKey"
            ]
          },
          "operations": [
            "localstack.services.kms.provider.KmsProvider.create_key",
            "localstack.services.kms.provider.KmsProvider.update_key_description"
          ],
          "api_limitations": {
            "localstack.services.kms.provider.KmsProvider.create_key": "Status 'Updating' is not supported."
          }
        },
    ...
    }
"""

import importlib
import inspect
import json
import pkgutil
from enum import Enum

import localstack.feature_catalog.services as feature_catalog
from localstack.feature_catalog.service_feature import ServiceFeature

# Automatically import all modules in the feature_catalog package
for _, module_name, _ in pkgutil.iter_modules(feature_catalog.__path__):
    importlib.import_module(f"{feature_catalog.__name__}.{module_name}")


def get_class_hierarchy(cls, level=0):
    # indent = " " * (level * 4)  # Indentation to reflect the level in the hierarchy
    # print(f"{indent}{cls.__name__}")  # Print the current class name
    for subclass in cls.__subclasses__():
        get_class_hierarchy(subclass, level + 1)  # Recursively get the hierarchy of subclasses


# Custom JSON Encoder for handling Enums
class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return str(obj)  # Serialize enum by returning its value
        return json.JSONEncoder.default(self, obj)


def get_class_hierarchy_dict(cls):
    hierarchy = {}
    docs = {
        key: value
        for key, value in vars(cls).items()
        if not callable(value) and not key.startswith("__")
    }
    if docs:
        hierarchy["docs"] = docs
    for subclass in cls.__subclasses__():
        hierarchy[subclass.__name__] = get_class_hierarchy_dict(subclass)

        # Recursive call
    return hierarchy


def find_decorated_functions_and_methods(module):
    decorated_functions = []

    # Search all members of the module
    for name, obj in inspect.getmembers(module):
        # If it's a function (not inside a class)
        if feature := getattr(obj, "feature", None):
            while (wrapped := getattr(obj, "__wrapped__", False)) and isinstance(
                wrapped, ServiceFeature
            ):
                # if the operation on the subclass has a decorator, unwrap it
                obj = wrapped
            feature_catalog_name = obj.__class__.__name__
            base_class = obj.__class__
            while base := base_class.__base__:
                if base.__name__ == "object":
                    break
                feature_catalog_name = f"{base.__name__}.{feature_catalog_name}"
                base_class = base
            decorated_functions.append(
                {
                    "feature_catalog_name": feature_catalog_name,
                    "name": name,
                    "feature": feature,
                    "fully_qualified_name": f"{module.__name__}.{name}",
                }
            )

        # If it's a class, check its methods
        elif inspect.isclass(obj):
            for method_name, method in inspect.getmembers(obj):
                limitation = getattr(method, "api_limitation_message", None)

                # TODO currently limitations are only collected if the api operation also has a feature decorator
                if feature := getattr(method, "feature", None):
                    while (wrapped := getattr(method, "__wrapped__", False)) and isinstance(
                        wrapped, ServiceFeature
                    ):
                        # if the operation on the subclass has a decorator, unwrap it
                        method = wrapped
                    # construct the feature_catalog_name, e.g. the hierarchy of the feature
                    # this will be used later on iterate the dict, and make sure the operation is added for the
                    # correct feature
                    feature_catalog_name = method.__class__.__name__
                    base_class = method.__class__
                    while base := base_class.__base__:
                        if base.__name__ == "object":
                            break
                        feature_catalog_name = f"{base.__name__}.{feature_catalog_name}"
                        base_class = base
                    decorated_functions.append(
                        {
                            "feature_catalog_name": feature_catalog_name,
                            "function_name": f"{name}.{method_name}",
                            "feature": feature,
                            "fully_qualified_name": f"{module.__name__}.{name}.{method_name}",
                            "limitations": limitation or "",
                        }
                    )

    return decorated_functions


def find_decorated_functions_in_package(package):
    decorated_functions = []

    # Iterate through all modules in the package
    for module_info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{module_info.name}")

        # Find decorated functions and methods within the module
        features = find_decorated_functions_and_methods(module)
        if features:
            decorated_functions.append({"module": module.__name__, "features": features})

    return decorated_functions


def recursive_add_operation(keys, current_dict, operation_name, limitations):
    key = keys[0]  # Take the first key
    for item in current_dict:
        if key in item:
            if len(keys) == 1:
                current_dict[key].setdefault("operations", []).append(operation_name)
                if limitations:
                    current_dict[key].setdefault("api_limitations", {})[operation_name] = (
                        limitations
                    )
            else:
                # Continue recursively with the remaining keys
                recursive_add_operation(keys[1:], current_dict[key], operation_name, limitations)


# Usage: Find all decorated functions in the entire cloudwatch package
import localstack.services.cloudwatch as cloudwatch_package
import localstack.services.kms as kms_package

features = {"ServiceFeature": get_class_hierarchy_dict(ServiceFeature)}
# print(json.dumps(features, indent=2, cls=EnumEncoder))
decorated_funcs = find_decorated_functions_in_package(cloudwatch_package)
decorated_funcs += find_decorated_functions_in_package(kms_package)

for details in decorated_funcs:
    module = details.get("module")
    for feature in details.get("features"):
        feature_catalog_keys = feature.get("feature_catalog_name").split(".")
        recursive_add_operation(
            feature_catalog_keys,
            features,
            feature.get("fully_qualified_name"),
            feature.get("limitations"),
        )

print(json.dumps(features, indent=2, cls=EnumEncoder))
