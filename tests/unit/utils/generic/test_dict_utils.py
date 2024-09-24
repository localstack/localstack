import unittest

from localstack.utils.collections import (
    dict_multi_values,
    get_safe,
    pick_attributes,
    set_safe_mutable,
)


class GenericDictUtilsTest(unittest.TestCase):
    def test_get_safe(self):
        dictionary = {
            "level_one_1": {
                "level_two_1": {
                    "level_three_1": "level_three_1_value",
                    "level_three_2": ["one", "two"],
                },
                "level_two_2": "level_two_2_value",
            },
            "level_one_2": "level_one_2_value",
        }

        self.assertEqual(
            dictionary["level_one_1"]["level_two_1"],
            get_safe(dictionary, "$.level_one_1.level_two_1"),
        )

        self.assertEqual(
            dictionary["level_one_1"]["level_two_1"],
            get_safe(dictionary, ["$", "level_one_1", "level_two_1"]),
        )

        self.assertEqual(
            "level_three_1_value",
            get_safe(dictionary, "$.level_one_1.level_two_1.level_three_1"),
        )

        self.assertEqual(
            "level_three_1_value",
            get_safe(dictionary, ["$", "level_one_1", "level_two_1", "level_three_1"]),
        )

        self.assertIsNone(
            get_safe(dictionary, ["$", "level_one_1", "level_two_1", "random", "value"])
        )

        self.assertEqual(
            "default_value",
            get_safe(
                dictionary,
                ["$", "level_one_1", "level_two_1", "random", "value"],
                "default_value",
            ),
        )

        self.assertEqual(
            "one",
            get_safe(dictionary, ["$", "level_one_1", "level_two_1", "level_three_2", "0"]),
        )

        self.assertEqual("two", get_safe(dictionary, "$.level_one_1.level_two_1.level_three_2.1"))

    def test_set_safe_mutable(self):
        mutable_dictionary = {}
        expected_dictionary = {
            "level_one_1": {
                "level_two_1": {"level_three_1": "level_three_1_value"},
                "level_two_2": "level_two_2_value",
            },
            "level_one_2": "level_one_2_value",
        }

        set_safe_mutable(
            mutable_dictionary,
            "$.level_one_1.level_two_1.level_three_1",
            "level_three_1_value",
        )
        set_safe_mutable(
            mutable_dictionary, ["$", "level_one_1", "level_two_2"], "level_two_2_value"
        )
        set_safe_mutable(mutable_dictionary, "$.level_one_2", "level_one_2_value")

        self.assertEqual(expected_dictionary, mutable_dictionary)

    def test_pick_attributes(self):
        dictionary = {
            "level_one_1": {
                "level_two_1": {"level_three_1": "level_three_1_value"},
                "level_two_2": "level_two_2_value",
            },
            "level_one_2": "level_one_2_value",
        }

        whitelisted_dictionary = pick_attributes(
            dictionary,
            [
                "$.level_one_1.level_two_1.level_three_1",
                ["$", "level_one_2"],
                "$.random.attribute",
            ],
        )

        expected_whitelisted_dictionary = {
            "level_one_1": {
                "level_two_1": {"level_three_1": "level_three_1_value"},
            },
            "level_one_2": "level_one_2_value",
        }
        self.assertEqual(expected_whitelisted_dictionary, whitelisted_dictionary)

    def test_dict_multi_values(self):
        tt = [
            {
                "input": {"a": 1, "b": 2},
                "expected": {"a": [1], "b": [2]},
            },
            {
                "input": ["a", "b"],
                "expected": {"a": ["b"]},
            },
            {
                "input": [["a", "1"], ["b", "2"], ["b", "3"]],
                "expected": {"a": ["1"], "b": ["2", "3"]},
            },
            {
                "input": {"a": [1, 2], "b": [3, 4]},
                "expected": {"a": [1, 2], "b": [3, 4]},
            },
        ]

        for t in tt:
            self.assertEqual(t["expected"], dict_multi_values(t["input"]))
