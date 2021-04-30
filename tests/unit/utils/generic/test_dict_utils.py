import unittest
from localstack.utils.generic.dict_utils import get_safe, set_safe_mutable, pick_attributes


class GenericDictUtilsTest(unittest.TestCase):

    def test_get_safe(self):
        dictionary = {
            'level_one_1': {
                'level_two_1': {
                    'level_three_1': 'level_three_1_value',
                    'level_three_2': ['one', 'two']
                },
                'level_two_2': 'level_two_2_value'
            },
            'level_one_2': 'level_one_2_value'
        }

        self.assertEqual(
            get_safe(dictionary, '$.level_one_1.level_two_1'),
            dictionary['level_one_1']['level_two_1']
        )

        self.assertEqual(
            get_safe(dictionary, ['$', 'level_one_1', 'level_two_1']),
            dictionary['level_one_1']['level_two_1']
        )

        self.assertEqual(
            get_safe(dictionary, '$.level_one_1.level_two_1.level_three_1'),
            'level_three_1_value'
        )

        self.assertEqual(
            get_safe(dictionary, ['$', 'level_one_1', 'level_two_1', 'level_three_1']),
            'level_three_1_value'
        )

        self.assertEqual(
            get_safe(dictionary, ['$', 'level_one_1', 'level_two_1', 'random', 'value']),
            None
        )

        self.assertEqual(
            get_safe(dictionary, ['$', 'level_one_1', 'level_two_1', 'random', 'value'], 'default_value'),
            'default_value'
        )

        self.assertEqual(
            get_safe(dictionary, ['$', 'level_one_1', 'level_two_1', 'level_three_2', '0']),
            'one'
        )

        self.assertEqual(
            get_safe(dictionary, '$.level_one_1.level_two_1.level_three_2.1'),
            'two'
        )

    def test_set_safe_mutable(self):
        mutable_dictionary = {}
        expected_dictionary = {
            'level_one_1': {
                'level_two_1': {
                    'level_three_1': 'level_three_1_value'
                },
                'level_two_2': 'level_two_2_value'
            },
            'level_one_2': 'level_one_2_value'
        }

        set_safe_mutable(mutable_dictionary, '$.level_one_1.level_two_1.level_three_1', 'level_three_1_value')
        set_safe_mutable(mutable_dictionary, ['$', 'level_one_1', 'level_two_2'], 'level_two_2_value')
        set_safe_mutable(mutable_dictionary, '$.level_one_2', 'level_one_2_value')

        self.assertEqual(mutable_dictionary, expected_dictionary)

    def test_pick_attributes(self):
        dictionary = {
            'level_one_1': {
                'level_two_1': {
                    'level_three_1': 'level_three_1_value'
                },
                'level_two_2': 'level_two_2_value'
            },
            'level_one_2': 'level_one_2_value'
        }

        whitelisted_dictionary = pick_attributes(
            dictionary,
            [
                '$.level_one_1.level_two_1.level_three_1',
                ['$', 'level_one_2'],
                '$.random.attribute'
            ]
        )

        self.assertEqual(whitelisted_dictionary, {
            'level_one_1': {
                'level_two_1': {
                    'level_three_1': 'level_three_1_value'
                },
            },
            'level_one_2': 'level_one_2_value'
        })
