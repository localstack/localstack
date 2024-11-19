import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class QueryLanguageTemplate(TemplateLoader):
    LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER = "%LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER%"

    BASE_PASS_JSONATA = os.path.join(_THIS_FOLDER, "statemachines/base_pass_jsonata.json5")
    BASE_PASS_JSONATA_OVERRIDE = os.path.join(
        _THIS_FOLDER, "statemachines/base_pass_jsonata_override.json5"
    )
    BASE_PASS_JSONATA_OVERRIDE_DEFAULT = os.path.join(
        _THIS_FOLDER, "statemachines/base_pass_jsonata_override_default.json5"
    )
    BASE_PASS_JSONPATH = os.path.join(_THIS_FOLDER, "statemachines/base_pass_jsonpath.json5")

    JSONATA_ASSIGN_JSONPATH_REF = os.path.join(
        _THIS_FOLDER, "statemachines/jsonata_assign_jsonpath_reference.json5"
    )
    JSONPATH_ASSIGN_JSONATA_REF = os.path.join(
        _THIS_FOLDER, "statemachines/jsonpath_assign_jsonata_reference.json5"
    )

    JSONPATH_OUTPUT_TO_JSONATA = os.path.join(
        _THIS_FOLDER, "statemachines/jsonpath_output_to_jsonata.json5"
    )
    JSONATA_OUTPUT_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/jsonata_output_to_jsonpath.json5"
    )

    JSONPATH_TO_JSONATA_DATAFLOW = os.path.join(
        _THIS_FOLDER, "statemachines/jsonpath_to_jsonata_dataflow.json5"
    )

    TASK_LAMBDA_SDK_RESOURCE_JSONATA_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_sdk_resource_from_jsonata_to_jsonpath.json5"
    )

    TASK_LAMBDA_LEGACY_RESOURCE_JSONATA_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_legacy_resource_from_jsonata_to_jsonpath.json5"
    )

    TASK_LAMBDA_SDK_RESOURCE_JSONPATH_TO_JSONATA = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_sdk_resource_from_jsonpath_to_jsonata.json5"
    )

    TASK_LAMBDA_LEGACY_RESOURCE_JSONPATH_TO_JSONATA = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_legacy_resource_from_jsonpath_to_jsonata.json5"
    )
