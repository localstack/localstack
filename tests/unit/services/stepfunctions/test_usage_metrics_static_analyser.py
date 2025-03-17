import json

import pytest

from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguageMode
from localstack.services.stepfunctions.asl.static_analyser.usage_metrics_static_analyser import (
    UsageMetricsStaticAnalyser,
)

BASE_PASS_JSONATA = json.dumps(
    {
        "QueryLanguage": "JSONata",
        "StartAt": "StartState",
        "States": {
            "StartState": {"Type": "Pass", "End": True},
        },
    }
)

BASE_PASS_JSONPATH = json.dumps(
    {
        "QueryLanguage": "JSONPath",
        "StartAt": "StartState",
        "States": {
            "StartState": {"Type": "Pass", "End": True},
        },
    }
)

BASE_PASS_JSONATA_OVERRIDE = json.dumps(
    {
        "QueryLanguage": "JSONPath",
        "StartAt": "StartState",
        "States": {
            "StartState": {"QueryLanguage": "JSONata", "Type": "Pass", "End": True},
        },
    }
)

BASE_PASS_JSONATA_OVERRIDE_DEFAULT = json.dumps(
    {
        "StartAt": "StartState",
        "States": {
            "StartState": {"QueryLanguage": "JSONata", "Type": "Pass", "End": True},
        },
    }
)

JSONPATH_TO_JSONATA_DATAFLOW = json.dumps(
    {
        "StartAt": "StateJsonPath",
        "States": {
            "StateJsonPath": {"Type": "Pass", "Assign": {"var": 42}, "Next": "StateJsonata"},
            "StateJsonata": {
                "QueryLanguage": "JSONata",
                "Type": "Pass",
                "Output": "{% $var %}",
                "End": True,
            },
        },
    }
)

ASSIGN_BASE_EMPTY = json.dumps(
    {"StartAt": "State0", "States": {"State0": {"Type": "Pass", "Assign": {}, "End": True}}}
)

ASSIGN_BASE_SCOPE_MAP = json.dumps(
    {
        "StartAt": "State0",
        "States": {
            "State0": {
                "Type": "Map",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Inner",
                    "States": {
                        "Inner": {
                            "Type": "Pass",
                            "Assign": {},
                            "End": True,
                        },
                    },
                },
                "End": True,
            }
        },
    }
)


class TestUsageMetricsStaticAnalyser:
    @pytest.mark.parametrize(
        "definition",
        [
            BASE_PASS_JSONATA,
            BASE_PASS_JSONATA_OVERRIDE,
            BASE_PASS_JSONATA_OVERRIDE_DEFAULT,
        ],
        ids=[
            "BASE_PASS_JSONATA",
            "BASE_PASS_JSONATA_OVERRIDE",
            "BASE_PASS_JSONATA_OVERRIDE_DEFAULT",
        ],
    )
    def test_jsonata(self, definition):
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert not analyser.uses_variables
        assert QueryLanguageMode.JSONata in analyser.query_language_modes

    @pytest.mark.parametrize(
        "definition",
        [
            BASE_PASS_JSONATA_OVERRIDE,
            BASE_PASS_JSONATA_OVERRIDE_DEFAULT,
        ],
        ids=[
            "BASE_PASS_JSONATA_OVERRIDE",
            "BASE_PASS_JSONATA_OVERRIDE_DEFAULT",
        ],
    )
    def test_both_query_languages(self, definition):
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert not analyser.uses_variables
        assert QueryLanguageMode.JSONata in analyser.query_language_modes
        assert QueryLanguageMode.JSONPath in analyser.query_language_modes

    @pytest.mark.parametrize("definition", [BASE_PASS_JSONPATH], ids=["BASE_PASS_JSONPATH"])
    def test_jsonpath(self, definition):
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert QueryLanguageMode.JSONata not in analyser.query_language_modes
        assert not analyser.uses_variables

    @pytest.mark.parametrize(
        "definition", [JSONPATH_TO_JSONATA_DATAFLOW], ids=["JSONPATH_TO_JSONATA_DATAFLOW"]
    )
    def test_jsonata_and_variable_sampling(self, definition):
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert QueryLanguageMode.JSONPath in analyser.query_language_modes
        assert QueryLanguageMode.JSONata in analyser.query_language_modes
        assert analyser.uses_variables

    @pytest.mark.parametrize(
        "definition",
        [
            ASSIGN_BASE_EMPTY,
            ASSIGN_BASE_SCOPE_MAP,
        ],
        ids=[
            "ASSIGN_BASE_EMPTY",
            "ASSIGN_BASE_SCOPE_MAP",
        ],
    )
    def test_jsonpath_and_variable_sampling(self, definition):
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert QueryLanguageMode.JSONata not in analyser.query_language_modes
        assert analyser.uses_variables
