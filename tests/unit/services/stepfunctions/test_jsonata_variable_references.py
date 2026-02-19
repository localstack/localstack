"""Unit tests for JSONata variable reference extraction.

Regression tests for https://github.com/localstack/localstack/issues/13579
"""

import pytest

from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    IllegalJSONataVariableReference,
    extract_jsonata_variable_references,
)


class TestExtractJsonataVariableReferences:
    def test_simple_variable(self):
        refs = extract_jsonata_variable_references("$states.input.foo")
        assert refs == {"$states.input.foo"}

    def test_multiple_variables(self):
        refs = extract_jsonata_variable_references(
            "$states.input.part1 + $states.input.part2"
        )
        assert refs == {"$states.input.part1", "$states.input.part2"}

    def test_variables_inside_array_literal(self):
        """Regression test for #13579: $merge with dynamic args returns {}."""
        refs = extract_jsonata_variable_references(
            "$merge([$states.input.part1, $states.input.part2])"
        )
        assert refs == {"$merge", "$states.input.part1", "$states.input.part2"}

    def test_variables_inside_nested_brackets(self):
        refs = extract_jsonata_variable_references("$append([$a, $b], [$c])")
        assert refs == {"$append", "$a", "$b", "$c"}

    def test_variable_with_bracket_field_access(self):
        """String literals inside brackets should be skipped by branch 2."""
        refs = extract_jsonata_variable_references('$states.input["field-name"]')
        assert refs == {"$states.input"}

    def test_variable_inside_string_literal_ignored(self):
        refs = extract_jsonata_variable_references('"$notavar"')
        assert refs == set()

    def test_variable_inside_single_quote_string_ignored(self):
        refs = extract_jsonata_variable_references("'$notavar'")
        assert refs == set()

    def test_variable_inside_regex_literal_ignored(self):
        refs = extract_jsonata_variable_references("/\\$pattern/i")
        assert refs == set()

    def test_empty_expression(self):
        refs = extract_jsonata_variable_references("")
        assert refs == set()

    def test_no_variables(self):
        refs = extract_jsonata_variable_references("1 + 2")
        assert refs == set()

    def test_lone_dollar_ignored(self):
        """Bare $ is the JSONata context variable (e.g. in filter predicates
        like [$ = 1]) — it should not be extracted as a variable reference."""
        refs = extract_jsonata_variable_references("$")
        assert refs == set()

    def test_double_dollar_raises(self):
        """$$ is the JSONata root input reference — it is captured by the regex
        but rejected as an illegal variable reference."""
        with pytest.raises(IllegalJSONataVariableReference):
            extract_jsonata_variable_references("$$")

    def test_filter_expression_with_variable(self):
        refs = extract_jsonata_variable_references("$data[$type]")
        assert refs == {"$data", "$type"}

    def test_filter_predicate_with_context_variable(self):
        """Filter predicates using bare $ (context variable) should not cause
        errors or be extracted. Regression test for MAP_TASK_STATE expressions
        like $count($states.result[$ = 1])."""
        refs = extract_jsonata_variable_references("$count($states.result[$ = 1])")
        assert refs == {"$count", "$states.result"}

    def test_filter_predicate_bare_dollar_equals_zero(self):
        refs = extract_jsonata_variable_references("$states.result[$ = 0]")
        assert refs == {"$states.result"}
