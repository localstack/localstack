import json

import pytest

from localstack.services.stepfunctions.asl.static_analyser.usage_metrics_static_analyser import (
    UsageMetricsStaticAnalyser,
)
from tests.aws.services.stepfunctions.templates.assign.assign_templates import (
    AssignTemplate,
)
from tests.aws.services.stepfunctions.templates.querylanguage.query_language_templates import (
    QueryLanguageTemplate,
)


class TestUsageMetricsStaticAnalyser:
    @staticmethod
    def _get_query_language_definition(query_language_template_filepath: str) -> str:
        template = QueryLanguageTemplate.load_sfn_template(query_language_template_filepath)
        definition = json.dumps(template)
        return definition

    @staticmethod
    def _get_variable_sampling_definition(variable_sampling_template_filepath: str) -> str:
        template = AssignTemplate.load_sfn_template(variable_sampling_template_filepath)
        definition = json.dumps(template)
        return definition

    @pytest.mark.parametrize(
        "template_filepath",
        [
            QueryLanguageTemplate.BASE_PASS_JSONATA,
            QueryLanguageTemplate.BASE_PASS_JSONATA_OVERRIDE,
            QueryLanguageTemplate.BASE_PASS_JSONATA_OVERRIDE_DEFAULT,
        ],
        ids=[
            "BASE_PASS_JSONATA",
            "BASE_PASS_JSONATA_OVERRIDE",
            "BASE_PASS_JSONATA_OVERRIDE_DEFAULT",
        ],
    )
    def test_jsonata(self, template_filepath):
        definition = self._get_query_language_definition(template_filepath)
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert analyser.has_jsonata
        assert not analyser.has_variable_sampling

    @pytest.mark.parametrize(
        "template_filepath",
        [
            QueryLanguageTemplate.BASE_PASS_JSONPATH,
        ],
        ids=["BASE_PASS_JSONPATH"],
    )
    def test_jsonpath(self, template_filepath):
        definition = self._get_query_language_definition(template_filepath)
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert not analyser.has_jsonata
        assert not analyser.has_variable_sampling

    @pytest.mark.parametrize(
        "template_filepath",
        [
            QueryLanguageTemplate.JSONPATH_TO_JSONATA_DATAFLOW,
            QueryLanguageTemplate.JSONPATH_ASSIGN_JSONATA_REF,
        ],
        ids=["JSONPATH_TO_JSONATA_DATAFLOW", "JSONPATH_ASSIGN_JSONATA_REF"],
    )
    def test_jsonata_and_variable_sampling(self, template_filepath):
        definition = self._get_query_language_definition(template_filepath)
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert analyser.has_jsonata
        assert analyser.has_variable_sampling

    @pytest.mark.parametrize(
        "template_filepath",
        [
            AssignTemplate.BASE_EMPTY,
            AssignTemplate.BASE_PATHS,
            AssignTemplate.BASE_SCOPE_MAP,
            AssignTemplate.BASE_ASSIGN_FROM_LAMBDA_TASK_RESULT,
            AssignTemplate.BASE_REFERENCE_IN_LAMBDA_TASK_FIELDS,
        ],
        ids=[
            "BASE_EMPTY",
            "BASE_PATHS",
            "BASE_SCOPE_MAP",
            "BASE_ASSIGN_FROM_LAMBDA_TASK_RESULT",
            "BASE_REFERENCE_IN_LAMBDA_TASK_FIELDS",
        ],
    )
    def test_jsonpath_and_variable_sampling(self, template_filepath):
        definition = self._get_query_language_definition(template_filepath)
        analyser = UsageMetricsStaticAnalyser.process(definition)
        assert not analyser.has_jsonata
        assert analyser.has_variable_sampling
