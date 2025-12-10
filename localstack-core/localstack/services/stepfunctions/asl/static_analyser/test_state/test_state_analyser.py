import json
from typing import Any, Final

# Botocore shape classes to drive validation
from botocore.model import (
    ListShape,
    MapShape,
    Shape,
    StringShape,
    StructureShape,
)

from localstack.aws.api.stepfunctions import (
    Definition,
    InvalidDefinition,
    MockInput,
    MockResponseValidationMode,
    StateName,
    TestStateInput,
    ValidationException,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.state_map import (
    StateMap,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.state_parallel import (
    StateParallel,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_api_gateway import (
    StateTaskServiceApiGateway,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.state_fail import StateFail
from localstack.services.stepfunctions.asl.component.state.state_pass.state_pass import StatePass
from localstack.services.stepfunctions.asl.component.state.state_succeed.state_succeed import (
    StateSucceed,
)
from localstack.services.stepfunctions.asl.component.state.state_type import StateType
from localstack.services.stepfunctions.asl.component.test_state.program.test_state_program import (
    TestStateProgram,
)
from localstack.services.stepfunctions.asl.parse.test_state.asl_parser import (
    TestStateAmazonStateLanguageParser,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser


class TestStateStaticAnalyser(StaticAnalyser):
    state_name: StateName | None

    def __init__(self, state_name: StateName | None = None):
        self.state_name = state_name

    _SUPPORTED_STATE_TYPES: Final[set[StateType]] = {
        StateType.Task,
        StateType.Pass,
        StateType.Wait,
        StateType.Choice,
        StateType.Succeed,
        StateType.Fail,
        StateType.Map,
    }

    @staticmethod
    def is_state_in_definition(definition: Definition, state_name: StateName) -> bool:
        test_program, _ = TestStateAmazonStateLanguageParser.parse(definition, state_name)
        if not isinstance(test_program, TestStateProgram):
            raise ValueError("expected parsed EvalComponent to be of type TestStateProgram")

        return test_program.test_state is not None

    @staticmethod
    def validate_role_arn_required(
        mock_input: MockInput, definition: Definition, state_name: StateName
    ) -> None:
        test_program, _ = TestStateAmazonStateLanguageParser.parse(definition, state_name)
        test_state = test_program.test_state
        if isinstance(test_state, StateTask) and mock_input is None:
            raise ValidationException("RoleArn must be specified when testing a Task state")

    @staticmethod
    def validate_mock(test_state_input: TestStateInput) -> None:
        test_program, _ = TestStateAmazonStateLanguageParser.parse(
            test_state_input.get("definition"), test_state_input.get("stateName")
        )
        test_state = test_program.test_state
        mock_input = test_state_input.get("mock")

        TestStateStaticAnalyser.validate_test_state_allows_mocking(
            mock_input=mock_input, test_state=test_state
        )

        if mock_input is None:
            return

        if test_state_input.get("revealSecrets"):
            raise ValidationException(
                "TestState does not support RevealSecrets when a mock is specified."
            )

        if {"result", "errorOutput"} <= mock_input.keys():
            raise ValidationException(
                "A test mock should have only one of the following fields: [result, errorOutput]."
            )

        mock_result_raw = mock_input.get("result")
        if mock_result_raw is None:
            return
        try:
            mock_result = json.loads(mock_result_raw)
        except json.JSONDecodeError:
            raise ValidationException("Mocked result must be valid JSON")

        if isinstance(test_state, StateMap):
            TestStateStaticAnalyser.validate_mock_result_matches_map_definition(
                mock_result=mock_result, test_state=test_state
            )

        if isinstance(test_state, StateTaskService):
            field_validation_mode = mock_input.get(
                "fieldValidationMode", MockResponseValidationMode.STRICT
            )
            TestStateStaticAnalyser.validate_mock_result_matches_api_shape(
                mock_result=mock_result,
                field_validation_mode=field_validation_mode,
                test_state=test_state,
            )

    @staticmethod
    def validate_test_state_allows_mocking(
        mock_input: MockInput, test_state: CommonStateField
    ) -> None:
        if mock_input is None and isinstance(test_state, (StateMap, StateParallel)):
            # This is a literal message when a Map or Parallel state is not accompanied by a mock in a test state request.
            # The message is the same for both cases and is not parametrised anyhow.
            raise InvalidDefinition(
                "TestState API does not support Map or Parallel states. Supported state types include: [Task, Wait, Pass, Succeed, Fail, Choice]"
            )

        if mock_input is not None and isinstance(test_state, (StatePass, StateFail, StateSucceed)):
            raise ValidationException(
                f"State type '{test_state.state_type.name}' is not supported when a mock is specified"
            )

    @staticmethod
    def validate_mock_result_matches_map_definition(mock_result: Any, test_state: StateMap):
        if test_state.result_writer is not None and not isinstance(mock_result, dict):
            raise ValidationException("Mocked result must be a JSON object.")

        if test_state.result_writer is None and not isinstance(mock_result, list):
            raise ValidationException("Mocked result must be an array.")

    @staticmethod
    def validate_mock_result_matches_api_shape(
        mock_result: Any,
        field_validation_mode: MockResponseValidationMode,
        test_state: StateTaskService,
    ):
        # apigateway:invoke: has no equivalent in the AWS SDK service integration.
        # Hence, the validation against botocore doesn't apply.
        # See the note in https://docs.aws.amazon.com/step-functions/latest/dg/connect-api-gateway.html
        # TODO do custom validation for apigateway:invoke:
        if isinstance(test_state, StateTaskServiceApiGateway):
            return

        if field_validation_mode == MockResponseValidationMode.NONE:
            return

        boto_service_name = test_state._get_boto_service_name()
        service_action_name = test_state._get_boto_service_action()
        output_shape = test_state._get_boto_operation_model(
            boto_service_name=boto_service_name, service_action_name=service_action_name
        ).output_shape

        # If the operation has no output, there's nothing to validate
        if output_shape is None:
            return

        def _raise_type_error(expected_type: str, field_name: str) -> None:
            raise ValidationException(
                f"Mock result schema validation error: Field '{field_name}' must be {expected_type}"
            )

        def _validate_value(value: Any, shape: Shape, field_name: str | None = None) -> None:
            # Document type accepts any JSON value
            if shape.type_name == "document":
                return

            if isinstance(shape, StructureShape):
                if not isinstance(value, dict):
                    # this is a defensive check, the mock result is loaded from JSON before, so should always be a dict
                    raise ValidationException(
                        f"Mock result must be a valid JSON object, but got '{type(value)}' instead"
                    )
                # Build a mapping from SFN-normalised member keys -> botocore member shapes
                members = shape.members
                sfn_key_to_member_shape: dict[str, Shape] = {
                    StateTaskService._to_sfn_cased(member_key): member_shape
                    for member_key, member_shape in members.items()
                }
                if field_validation_mode == MockResponseValidationMode.STRICT:
                    # Ensure required members are present, using SFN-normalised keys
                    for required_key in shape.required_members:
                        sfn_required_key = StateTaskService._to_sfn_cased(required_key)
                        if sfn_required_key not in value:
                            raise ValidationException(
                                f"Mock result schema validation error: Required field '{sfn_required_key}' is missing"
                            )
                # Validate present fields (match SFN-normalised keys to member shapes)
                for mock_field_name, mock_field_value in value.items():
                    member_shape = sfn_key_to_member_shape.get(mock_field_name)
                    if member_shape is None:
                        # Fields that are present in mock but are not in the API spec should not raise validation errors - forward compatibility
                        continue
                    _validate_value(mock_field_value, member_shape, mock_field_name)
                return

            if isinstance(shape, ListShape):
                if not isinstance(value, list):
                    _raise_type_error("an array", field_name)
                member_shape = shape.member
                for list_item in value:
                    _validate_value(list_item, member_shape, field_name)
                return

            if isinstance(shape, MapShape):
                if not isinstance(value, dict):
                    _raise_type_error("an object", field_name)
                value_shape = shape.value
                for _, map_item_value in value.items():
                    _validate_value(map_item_value, value_shape, field_name)
                return

            # Primitive shapes and others
            type_name = shape.type_name
            match type_name:
                case "string" | "timestamp":
                    if not isinstance(value, str):
                        _raise_type_error("a string", field_name)
                    # Validate enum if present
                    if isinstance(shape, StringShape):
                        enum = getattr(shape, "enum", None)
                        if enum and value not in enum:
                            raise ValidationException(
                                f"Mock result schema validation error: Field '{field_name}' is not an expected value"
                            )

                case "integer" | "long":
                    if not isinstance(value, int) or isinstance(value, bool):
                        _raise_type_error("a number", field_name)

                case "float" | "double":
                    if not (isinstance(value, (int, float)) or isinstance(value, bool)):
                        _raise_type_error("a number", field_name)

                case "boolean":
                    if not isinstance(value, bool):
                        _raise_type_error("a boolean", field_name)

                case "blob":
                    if not (isinstance(value, (str, bytes))):
                        _raise_type_error("a string", field_name)

        # Perform validation against the output shape
        _validate_value(mock_result, output_shape)

    def analyse(self, definition: str) -> None:
        _, parser_rule_context = TestStateAmazonStateLanguageParser.parse(
            definition, self.state_name
        )
        self.visit(parser_rule_context)

    def visitState_type(self, ctx: ASLParser.State_typeContext) -> None:
        state_type_value: int = ctx.children[0].symbol.type
        state_type = StateType(state_type_value)
        if state_type not in self._SUPPORTED_STATE_TYPES:
            raise ValueError(f"Unsupported state type for TestState runs '{state_type}'.")
