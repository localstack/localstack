import pytest
from antlr4 import CommonTokenStream, InputStream

from localstack.aws.api.stepfunctions import StateMachineType
from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value_object import (
    AssignTemplateValueObject,
)
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguage,
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.evaluation_details import AWSExecutionDetails
from localstack.services.stepfunctions.asl.eval.event.event_manager import EventHistoryContext
from localstack.services.stepfunctions.asl.eval.program_state import ProgramRunning
from localstack.services.stepfunctions.asl.eval.states import (
    ContextObjectData,
    ExecutionData,
    StateMachineData,
)
from localstack.services.stepfunctions.asl.parse.preprocessor import Preprocessor

POSITIVE_SCENARIOS = [
    (
        "base_string_bindings",
        """{
            "jsonataexpr": "{% ($name := 'NameString'; $name) %}",
            "stringlit1": " {% ($name := 'NameString'; $name) %}",
            "stringlit2": "{% ($name := 'NameString'; $name) %} ",
            "stringlit3": "stringlit",
            "stringlig4": "$.stringlit",
            "stringlig5": "$.stringlit"
        }""",
        {
            "jsonataexpr": "NameString",
            "stringlit1": " {% ($name := 'NameString'; $name) %}",
            "stringlit2": "{% ($name := 'NameString'; $name) %} ",
            "stringlit3": "stringlit",
            "stringlig4": "$.stringlit",
            "stringlig5": "$.stringlit",
        },
    ),
    (
        "base_types",
        """{
            "jsonataexpr": "{% ($name := 'namestring'; $name) %}",
            "null": null,
            "int": 1,
            "float": 0.1,
            "boolt": true,
            "boolf": false,
            "arr": [null, 1, 0.1, true, [], {"jsonataexpr": "{% ($name := 'namestring'; $name) %}"}],
            "obj": {"jsonataexpr": "{% ($name := 'namestring'; $name) %}"}
        }""",
        {
            "jsonataexpr": "namestring",
            "null": None,
            "int": 1,
            "float": 0.1,
            "boolf": False,
            "boolt": True,
            "arr": [None, 1, 0.1, True, [], {"jsonataexpr": "namestring"}],
            "obj": {"jsonataexpr": "namestring"},
        },
    ),
]
POSITIVE_SCENARIOS_IDS = [scenario[0] for scenario in POSITIVE_SCENARIOS]
POSITIVE_SCENARIOS_EXPR_OUTPUT_PARIS = [tuple(scenario[1:]) for scenario in POSITIVE_SCENARIOS]


def parse_payload(payload_derivation: str) -> AssignTemplateValueObject:
    input_stream = InputStream(payload_derivation)
    lexer = ASLLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = ASLParser(stream)
    tree = parser.assign_template_value_object()
    preprocessor = Preprocessor()
    # simulate a jsonata query language top level definition.
    preprocessor._query_language_per_scope.append(
        QueryLanguage(query_language_mode=QueryLanguageMode.JSONata)
    )
    jsonata_payload_object = preprocessor.visit(tree)
    preprocessor._query_language_per_scope.clear()
    return jsonata_payload_object


def evaluate_payload(jsonata_payload_object: AssignTemplateValueObject) -> dict:
    env = Environment(
        aws_execution_details=AWSExecutionDetails("test-account", "test-region", "test-role"),
        execution_type=StateMachineType.STANDARD,
        context=ContextObjectData(
            Execution=ExecutionData(
                Id="test-exec-arn",
                Input=dict(),
                Name="test-name",
                RoleArn="test-role",
                StartTime="test-start-time",
            ),
            StateMachine=StateMachineData(Id="test-arn", Name="test-name"),
        ),
        event_history_context=EventHistoryContext.of_program_start(),
        cloud_watch_logging_session=None,
        activity_store=dict(),
    )
    env._program_state = ProgramRunning()
    jsonata_payload_object.eval(env)
    return env.stack.pop()


class TestJSONataPayload:
    @pytest.mark.parametrize(
        "derivation, output",
        POSITIVE_SCENARIOS_EXPR_OUTPUT_PARIS,
        ids=POSITIVE_SCENARIOS_IDS,
    )
    def test_derivation_positive(self, derivation, output):
        jsonata_payload_object = parse_payload(derivation)
        result = evaluate_payload(jsonata_payload_object)
        assert result == output
