# import json
#
# import pytest
#
# from localstack.services.stepfunctions.templates.querylanguage.query_language_templates import (
#     QueryLanguageTemplate,
# )
# from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguageMode
# from localstack.services.stepfunctions.asl.component.program.program import Program
# from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
#
#
# class TestJSONataIntegration:
#     # TODO add test cases for MAP and Parallel states, but docs aren't specific enough.
#
#     @staticmethod
#     def _parse_template_file(query_language_template_filepath: str) -> Program:
#         template = QueryLanguageTemplate.load_sfn_template(query_language_template_filepath)
#         definition = json.dumps(template)
#         program: Program = AmazonStateLanguageParser.parse(definition)[0]  # noqa
#         return program
#
#     def test_pass_jsonata(self):
#         program: Program = self._parse_template_file(QueryLanguageTemplate.BASE_PASS_JSONATA)
#         assert program.query_language.query_language_mode == QueryLanguageMode.JSONata
#         assert (
#             program.states.states["StartState"].query_language.query_language_mode
#             == QueryLanguageMode.JSONata
#         )
#
#     @pytest.mark.parametrize(
#         "template_filepath",
#         [
#             QueryLanguageTemplate.BASE_PASS_JSONATA_OVERRIDE,
#             QueryLanguageTemplate.BASE_PASS_JSONATA_OVERRIDE_DEFAULT,
#         ],
#         ids=["BASE_PASS_JSONATA_OVERRIDE", "BASE_PASS_JSONATA_OVERRIDE_DEFAULT"],
#     )
#     def test_pass_jsonata_override(self, template_filepath):
#         program: Program = self._parse_template_file(template_filepath)
#         assert program.query_language.query_language_mode == QueryLanguageMode.JSONPath
#         assert (
#             program.states.states["StartState"].query_language.query_language_mode
#             == QueryLanguageMode.JSONata
#         )
#
#     def test_base_pass_jsonpath(self):
#         program: Program = self._parse_template_file(QueryLanguageTemplate.BASE_PASS_JSONPATH)
#         assert program.query_language.query_language_mode == QueryLanguageMode.JSONPath
#         assert (
#             program.states.states["StartState"].query_language.query_language_mode
#             == QueryLanguageMode.JSONPath
#         )
