import localstack.services.cloudformation.provider_utils as utils


class TestDictUtils:
    def test_convert_values_to_numbers(self):
        original = {"Parameter": "1", "SecondParameter": ["2", "2"], "ThirdParameter": "3"}
        transformed = utils.convert_values_to_numbers(original, ["ThirdParameter"])

        assert original["Parameter"] == "1"
        assert transformed["Parameter"] == 1
        assert transformed["SecondParameter"][0] == 2
        assert transformed["ThirdParameter"] == "3"
