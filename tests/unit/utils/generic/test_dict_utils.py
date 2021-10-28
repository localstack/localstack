import unittest

from localstack.utils.generic.dict_utils import get_safe, pick_attributes, set_safe_mutable


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
