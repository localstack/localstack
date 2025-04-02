import json

import pytest

from localstack.aws.api.stepfunctions import StateMachineType
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates,
)
from tests.aws.services.stepfunctions.templates.validation.validation_templates import (
    ValidationTemplate,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..diagnostics",  # TODO: add support for diagnostics
    ]
)
class TestSfnApiValidation:
    @pytest.mark.parametrize(
        "definition_string",
        [" ", "not a definition", "{}"],
        ids=["EMPTY_STRING", "NOT_A_DEF", "EMPTY_DICT"],
    )
    @markers.aws.validated
    def test_validate_state_machine_definition_not_a_definition(
        self, sfn_snapshot, aws_client, definition_string
    ):
        validation_response = aws_client.stepfunctions.validate_state_machine_definition(
            definition=definition_string, type=StateMachineType.STANDARD
        )
        sfn_snapshot.match("validation_response", validation_response)

    @pytest.mark.parametrize(
        "validation_template",
        [ValidationTemplate.VALID_BASE_PASS, ValidationTemplate.INVALID_BASE_NO_STARTAT],
        ids=["VALID_BASE_PASS", "INVALID_BASE_NO_STARTAT"],
    )
    @markers.aws.validated
    def test_validate_state_machine_definition_type_standard(
        self, sfn_snapshot, aws_client, validation_template
    ):
        definition = ValidationTemplate.load_sfn_template(validation_template)
        definition_str = json.dumps(definition)
        validation_response = aws_client.stepfunctions.validate_state_machine_definition(
            definition=definition_str, type=StateMachineType.STANDARD
        )
        sfn_snapshot.match("validation_response", validation_response)

    @pytest.mark.parametrize(
        "validation_template",
        [
            ValidationTemplate.VALID_BASE_PASS,
            ValidationTemplate.INVALID_BASE_NO_STARTAT,
            CallbackTemplates.SQS_WAIT_FOR_TASK_TOKEN,
        ],
        ids=["VALID_BASE_PASS", "INVALID_BASE_NO_STARTAT", "ILLEGAL_WFTT"],
    )
    @markers.aws.validated
    def test_validate_state_machine_definition_type_express(
        self, sfn_snapshot, aws_client, validation_template
    ):
        definition = ValidationTemplate.load_sfn_template(validation_template)
        definition_str = json.dumps(definition)
        validation_response = aws_client.stepfunctions.validate_state_machine_definition(
            definition=definition_str, type=StateMachineType.EXPRESS
        )
        sfn_snapshot.match("validation_response", validation_response)
