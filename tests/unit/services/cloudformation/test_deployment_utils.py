from localstack.services.cloudformation.deployment_utils import fix_boto_parameters_based_on_report


class TestFixBotoParametersBasedOnReport:
    def test_nested_parameters_are_fixed(self):
        params = {"LaunchTemplate": {"Version": 1}}
        message = (
            "Invalid type for parameter LaunchTemplate.Version, "
            "value: 1, type: <class 'int'>, valid types: <class 'str'>"
        )

        fixed_params = fix_boto_parameters_based_on_report(params, message)
        value = fixed_params["LaunchTemplate"]["Version"]
        assert value == "1"
        assert type(value) == str

    def test_top_level_parameters_are_converted(self):
        params = {"Version": 1}
        message = "Invalid type for parameter Version, value: 1, type: <class 'int'>, valid types: <class 'str'>"

        fixed_params = fix_boto_parameters_based_on_report(params, message)
        value = fixed_params["Version"]
        assert value == "1"
        assert type(value) == str
