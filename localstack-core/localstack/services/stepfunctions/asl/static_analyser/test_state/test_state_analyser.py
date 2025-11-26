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
    MockInput,
    MockResponseValidationMode,
    StateName,
    ValidationException,
)
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ActivityResource,
    Resource,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
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
    def validate_mock(mock_input: MockInput, definition: Definition, state_name: StateName) -> None:
        test_program, _ = TestStateAmazonStateLanguageParser.parse(definition, state_name)
        test_state = test_program.test_state
        if isinstance(test_state, StateTaskService):
            field_validation_mode = mock_input.get(
                "fieldValidationMode", MockResponseValidationMode.STRICT
            )
            mock_result_raw = mock_input.get("result")
            if mock_result_raw is None:
                return
            try:
                mock_result = json.loads(mock_result_raw)
            except json.JSONDecodeError:
                raise ValidationException("Mocked result must be valid JSON")
            if mock_result is None or field_validation_mode == MockResponseValidationMode.NONE:
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
                        if not (isinstance(value, (int, float)) and not isinstance(value, bool)):
                            _raise_type_error("a number", field_name)

                    case "boolean":
                        if not isinstance(value, bool):
                            _raise_type_error("a boolean", field_name)

                    case "blob":
                        if not (isinstance(value, (str, bytes))):
                            _raise_type_error("a string", field_name)

            # Perform validation against the output shape
            _validate_value(mock_result, output_shape)
        # Non-service tasks or other cases: nothing to validate
        return

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

    def visitResource_decl(self, ctx: ASLParser.Resource_declContext) -> None:
        resource_str: str = ctx.string_literal().getText()[1:-1]
        resource = Resource.from_resource_arn(resource_str)

        if isinstance(resource, ActivityResource):
            raise ValueError(
                f"ActivityResources are not supported for TestState runs {resource_str}."
            )

        if isinstance(resource, ServiceResource):
            if resource.condition is not None:
                raise ValueError(
                    f"Service integration patterns are not supported for TestState runs {resource_str}."
                )
