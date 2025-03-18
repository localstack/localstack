import pytest

from localstack.services.events.event_rule_engine import EventRuleEngine


class TestEventRuler:
    @pytest.mark.parametrize(
        "input_pattern,flat_patterns",
        [
            (
                {"filter": [{"anything-but": {"prefix": "type"}}]},
                [{"filter": [{"anything-but": {"prefix": "type"}}]}],
            ),
            (
                {"field1": {"field2": {"field3": "val1", "field4": "val2"}}},
                [{"field1.field2.field3": "val1", "field1.field2.field4": "val2"}],
            ),
            (
                {"$or": [{"field1": "val1"}, {"field2": "val2"}], "field3": "val3"},
                [{"field1": "val1", "field3": "val3"}, {"field2": "val2", "field3": "val3"}],
            ),
        ],
        ids=["simple", "simple-with-dots", "$or-pattern"],
    )
    def test_flatten_patterns(self, input_pattern, flat_patterns):
        engine = EventRuleEngine()
        assert engine.flatten_pattern(input_pattern) == flat_patterns

    @pytest.mark.parametrize(
        "input_payload,flat_patterns,flat_payload",
        [
            (
                {"field1": "val1", "field3": "val3"},
                [{"field1": "val1", "field3": "val3"}, {"field2": "val2", "field3": "val3"}],
                [{"field1": "val1", "field3": "val3"}],
            ),
            (
                {"f1": {"f2": {"f3": "v3"}}, "f4": "v4"},
                [{"f4": "test1"}],
                [{"f4": "v4"}],
            ),
            (
                {"f1": {"f2": {"f3": {"f4": [{"f5": "v5"}]}, "f6": [{"f8": "v8"}]}}},
                [{"f1.f2.f3": "val1", "f1.f2.f4": "val2"}],
                [{}],
            ),
            (
                {"f1": {"f2": {"f3": {"f4": [{"f5": "v5"}]}, "f6": [{"f7": "v7"}]}}},
                [{"f1.f2.f3.f4.f5": "val1", "f1.f2.f4": "val2"}],
                [{"f1.f2.f3.f4.f5": "v5"}],
            ),
            (
                {"f1": {"f2": {"f3": {"f4": [{"f5": "v5"}]}, "f6": [{"f7": "v7"}]}}},
                [{"f1.f2.f3.f4.f5": "test1", "f1.f2.f6.f7": "test2"}],
                [{"f1.f2.f3.f4.f5": "v5", "f1.f2.f6.f7": "v7"}],
            ),
        ],
        ids=[
            "simple-with-or-pattern-flat",
            "simple-pattern-filter",
            "nested-payload-no-result",
            "nested-payload-1-match",
            "nested-payload-2-match",
        ],
    )
    def test_flatten_payload(self, input_payload, flat_patterns, flat_payload):
        engine = EventRuleEngine()

        assert engine.flatten_payload(input_payload, flat_patterns) == flat_payload
