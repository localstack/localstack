import json
from typing import Final

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateMachineTemplate as TSMT,
)

TEST_STATE_NAME: Final[str] = "State0"

HELLO_WORLD_INPUT = json.dumps({"Value": "HelloWorld"})

BASE_TEMPLATE_INPUT_BINDINGS: list[tuple[str, str, str]] = [
    (TSMT.BASE_PASS_STATE_MACHINE, "State0", HELLO_WORLD_INPUT),
    (TSMT.BASE_FAIL_STATE_MACHINE, "State0", HELLO_WORLD_INPUT),
    (TSMT.BASE_MAP_STATE_MACHINE, "HandleItem", HELLO_WORLD_INPUT),
]

IDS_BASE_TEMPLATE_INPUT_BINDINGS: list[str] = [
    "BASE_PASS_STATE_MACHINE",
    "BASE_FAIL_STATE_MACHINE",
    "BASE_MAP_STATE_MACHINE",
]


class TestStateMachineScenarios:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "tct_template,state_name,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_state_name(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        tct_template,
        state_name,
        execution_input,
        inspection_level,
    ):
        template = TSMT.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName=state_name,
            definition=definition,
            input=execution_input,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize("state_name", ["State0", "State1"])
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_state_name_multi_state(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        state_name,
        inspection_level,
    ):
        template = TSMT.load_sfn_template(TSMT.BASE_MULTI_STATE_MACHINE)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName=state_name,
            definition=definition,
            input=HELLO_WORLD_INPUT,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "state_name",
        ["dne", '"invalid"', ""],
        ids=["dne", "invalid", "empty"],
    )
    def test_base_state_name_validation_failures(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        state_name,
    ):
        template = TSMT.load_sfn_template(TSMT.BASE_PASS_STATE_MACHINE)
        definition = json.dumps(template)

        with pytest.raises(Exception) as ex:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                stateName=state_name,
                definition=definition,
                input=HELLO_WORLD_INPUT,
                inspectionLevel=InspectionLevel.INFO,
            )

        sfn_snapshot.match(
            "exception", {"exception_typename": ex.typename, "exception_value": ex.value}
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..message"])
    # ANTLR parser message has different wording but the same meaning as AWS response. Not investing time now to convert to the exact same wording - relying on error code for test.
    # TODO match wording and hide implementation details (ANTLR)
    # expected:
    # /Error/Message "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: The field 'Type' should have one of these values: [Task, Wait, Pass, Succeed, Fail, Choice, Parallel, Map] at /States/ExistingButInvalidState/Type'"
    # actual:
    # 'ASLParserException line 1:170, at "TypeThatDoesNotExist", mismatched input \'"TypeThatDoesNotExist"\' expecting {\'"Task"\', \'"Choice"\', \'"Fail"\', \'"Succeed"\', \'"Pass"\', \'"Wait"\', \'"Parallel"\', \'"Map"\'}'
    def test_state_name_invalid_state_definition(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TSMT.load_sfn_template(TSMT.BASE_INVALID_STATE_DEFINITION)
        definition = json.dumps(template)

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                stateName="ExistingButInvalidState",
                definition=definition,
                input=HELLO_WORLD_INPUT,
                inspectionLevel=InspectionLevel.INFO,
            )
        sfn_snapshot.match("validation_exception", e.value.response)
