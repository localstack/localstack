import pytest

from localstack.services.stepfunctions.asl.eval.states import (
    ContextObjectData,
    ExecutionData,
    StateMachineData,
    States,
)
from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    IllegalJSONataVariableReference,
    JSONataException,
    JSONataExpression,
    VariableDeclarations,
    VariableReference,
    compose_jsonata_expression,
    encode_jsonata_variable_declarations,
    eval_jsonata_expression,
    extract_jsonata_variable_references,
)

POSITIVE_SCENARIOS = [
    (
        "base_int_out",
        """(
        $x := 10;
        $x)""",
        10,
    ),
    (
        "base_float_out",
        """(
        $x := 10.1;
        $x)""",
        10.1,
    ),
    (
        "base_bool_out",
        """(
        $x := true;
        $x)""",
        True,
    ),
    (
        "base_array_out",
        """(
        $x := [1,2,3];
        $x)""",
        [1, 2, 3],
    ),
    (
        "base_object_out",
        """(
        $x := {
            "value": 1
        };
        $x)""",
        {"value": 1},
    ),
    (
        "expression_int_out",
        """(
        $obj := {
            "value": 99
        };
        $values := [3, 3];
        $x := 10;
        $obj.value+ $sum($values) + $x)""",
        115,
    ),
]
POSITIVE_SCENARIOS_IDS = [scenario[0] for scenario in POSITIVE_SCENARIOS]
POSITIVE_SCENARIOS_EXPR_OUTPUT_PARIS = [tuple(scenario[1:]) for scenario in POSITIVE_SCENARIOS]


NEGATIVE_SCENARIOS = [("null-input", None), ("empty-input", ""), ("syntax-error-semi", ";")]
NEGATIVE_SCENARIOS_IDS = [scenario[0] for scenario in NEGATIVE_SCENARIOS]
NEGATIVE_SCENARIOS_EXPRESSIONS = [scenario[1] for scenario in NEGATIVE_SCENARIOS]


VARIABLE_ASSIGNMENT_ENCODING = [
    ("int", {"$var1": 3}, "$var1:=3;"),
    ("float", {"$var1": 3.2}, "$var1:=3.2;"),
    ("null", {"$var1": None}, "$var1:=null;"),
    ("string", {"$var1": "string_lit"}, '$var1:="string_lit";'),
    ("list", {"$var1": [3, 3.2, None, "string_lit", []]}, '$var1:=[3,3.2,null,"string_lit",[]];'),
    (
        "obj",
        {"$var1": {"string_lit": "string_lit_value"}},
        '$var1:={"string_lit":"string_lit_value"};',
    ),
    (
        "mult",
        {
            "$var0": 0,
            "$var1": {"string_lit": "string_lit_value"},
            "$var2": [3, 3.2, None, "string_lit", []],
        },
        '$var0:=0;$var1:={"string_lit":"string_lit_value"};$var2:=[3,3.2,null,"string_lit",[]];',
    ),
]
VARIABLE_ASSIGNMENT_ENCODING_IDS = [scenario[0] for scenario in VARIABLE_ASSIGNMENT_ENCODING]
VARIABLE_ASSIGNMENT_ENCODING_SCENARIOS = [
    tuple(scenario[1:]) for scenario in VARIABLE_ASSIGNMENT_ENCODING
]

STATES_ACCESSES_STATES = States(
    context=ContextObjectData(
        Execution=ExecutionData(
            Id="test-exec-arn",
            Input={"items": [None, 1, 1.1, True, [], {"key": "string_lit"}]},
            Name="test-name",
            RoleArn="test-role",
            StartTime="test-start-time",
        ),
        StateMachine=StateMachineData(Id="test-arn", Name="test-name"),
    )
)
STATES_ACCESSES_STATES.set_result({"result_key": "result_value"})
STATES_ACCESSES = [
    ("input", "$states.input", {"items": [None, 1, 1.1, True, [], {"key": "string_lit"}]}),
    ("input.items", "$states.input.items", [None, 1, 1.1, True, [], {"key": "string_lit"}]),
    (
        "input.items-result",
        "[$states.input.items, $states.result]",
        [None, 1, 1.1, True, [], {"key": "string_lit"}, {"result_key": "result_value"}],
    ),
]
STATES_ACCESSES_IDS = [scenario[0] for scenario in STATES_ACCESSES]
STATES_ACCESSES_SCENARIOS = [tuple(scenario[1:]) for scenario in STATES_ACCESSES]


class TestJSONataIntegration:
    @pytest.mark.parametrize(
        "expression, expected",
        POSITIVE_SCENARIOS_EXPR_OUTPUT_PARIS,
        ids=POSITIVE_SCENARIOS_IDS,
    )
    def test_expressions_positive(self, expression, expected):
        result = eval_jsonata_expression(expression)
        assert result == expected

    @pytest.mark.parametrize(
        "expression",
        NEGATIVE_SCENARIOS_EXPRESSIONS,
        ids=NEGATIVE_SCENARIOS_IDS,
    )
    def test_expressions_negative(self, expression):
        with pytest.raises(JSONataException):
            eval_jsonata_expression(expression)

    def test_variable_assignment_extraction_positive(self):
        expression = "$a;$a0;$a0_;$a_0;$_a;$var1.var2.var3;$var$;$va$r;$_0a$.b$0;$var$$;$va$r$$.b$$"
        references = extract_jsonata_variable_references(expression)
        assert sorted(references) == sorted(expression.split(";"))

    def test_variable_assignment_extraction_negative(self):
        illegal_expressions = ["$", "$$"]
        for illegal_expression in illegal_expressions:
            with pytest.raises(IllegalJSONataVariableReference):
                extract_jsonata_variable_references(illegal_expression)

    @pytest.mark.parametrize(
        "bindings, expected",
        VARIABLE_ASSIGNMENT_ENCODING_SCENARIOS,
        ids=VARIABLE_ASSIGNMENT_ENCODING_IDS,
    )
    def test_variable_assignment_encoding(self, bindings, expected):
        encoding = encode_jsonata_variable_declarations(bindings)
        assert encoding == expected

    @pytest.mark.parametrize(
        "expression, expected", STATES_ACCESSES_SCENARIOS, ids=STATES_ACCESSES_IDS
    )
    def test_states_access(self, expression, expected):
        variable_references: set[VariableReference] = extract_jsonata_variable_references(
            expression
        )
        variable_declarations: VariableDeclarations = (
            STATES_ACCESSES_STATES.to_variable_declarations(variable_references=variable_references)
        )
        rich_jsonata_expression: JSONataExpression = compose_jsonata_expression(
            final_jsonata_expression=expression, variable_declarations_list=[variable_declarations]
        )
        result = eval_jsonata_expression(rich_jsonata_expression)
        assert result == expected
