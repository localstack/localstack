import pytest

from localstack.utils.common import short_uid


def _assert(search_name, param_name, ssm_client):
    def do_assert(result):
        assert len(result) > 0
        assert param_name == result[0]["Name"]
        assert "123" == result[0]["Value"]

    response = ssm_client.get_parameter(Name=search_name)
    do_assert([response["Parameter"]])

    response = ssm_client.get_parameters(Names=[search_name])
    do_assert(response["Parameters"])


# TODO: fix AWS compatibility
class TestSSM:
    def test_describe_parameters(self, ssm_client):
        response = ssm_client.describe_parameters()
        assert "Parameters" in response
        assert isinstance(response["Parameters"], list)

    def test_put_parameters(self, ssm_client, create_parameter):
        param_name = f"param-{short_uid()}"
        create_parameter(
            Name=param_name,
            Description="test",
            Value="123",
            Type="String",
        )

        _assert(param_name, param_name, ssm_client)
        _assert(f"/{param_name}", param_name, ssm_client)  # TODO: not valid

    # TODO botocore.exceptions.ClientError: An error occurred (ValidationException) when calling the GetParameter operation: Parameter name: can't be prefixed with "ssm" (case-insensitive). If formed as a path, it can consist of sub-paths divided by slash symbol; each sub-path can be formed as a mix of letters, numbers and the following 3 symbols .-_
    def test_hierarchical_parameter(self, ssm_client, create_parameter):
        param_a = f"{short_uid()}"
        create_parameter(
            Name=f"/{param_a}/b/c",
            Value="123",
            Type="String",
        )

        _assert(f"/{param_a}/b/c", f"/{param_a}/b/c", ssm_client)
        _assert(f"/{param_a}//b//c", f"/{param_a}/b/c", ssm_client)
        _assert(f"{param_a}/b//c", f"/{param_a}/b/c", ssm_client)

    # TODO botocore.exceptions.ClientError: An error occurred (ValidationException) when calling the GetParameter operation: WithDecryption flag must be True for retrieving a Secret Manager secret.
    def test_get_secret_parameter(self, ssm_client, secretsmanager_client, create_secret):
        secret_name = f"test_secret-{short_uid()}"
        create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        result = ssm_client.get_parameter(Name=f"/aws/reference/secretsmanager/{secret_name}")
        assert f"/aws/reference/secretsmanager/{secret_name}" == result.get("Parameter").get("Name")
        assert "my_secret" == result.get("Parameter").get("Value")

        source_result = result.get("Parameter").get("SourceResult")
        assert source_result is not None, "SourceResult should be present"
        assert type(source_result) is str, "SourceResult should be a string"

    # TODO: botocore.exceptions.ClientError: An error occurred (ValidationException) when calling the GetParameter operation: WithDecryption flag must be True for retrieving a Secret Manager secret.
    def test_get_inexistent_secret(self, ssm_client):
        with pytest.raises(ssm_client.exceptions.ParameterNotFound):
            ssm_client.get_parameter(Name="/aws/reference/secretsmanager/inexistent")

    # TODO: AssertionError: assert '/aws/reference/secretsmanager/9763a545_test_secret_params' in ['inexistent_param', '/aws/reference/secretsmanager/inexistent_secret']
    def test_get_parameters_and_secrets(
        self, ssm_client, secretsmanager_client, create_parameter, create_secret
    ):
        param_name = f"param-{short_uid()}"
        secret_path = "/aws/reference/secretsmanager/"
        secret_name = f"{short_uid()}_test_secret_params"
        complete_secret = secret_path + secret_name

        create_parameter(
            Name=param_name,
            Description="test",
            Value="123",
            Type="String",
        )

        create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        response = ssm_client.get_parameters(
            Names=[
                param_name,
                complete_secret,
                "inexistent_param",
                secret_path + "inexistent_secret",
            ]
        )
        found = response.get("Parameters")
        not_found = response.get("InvalidParameters")

        for param in found:
            assert param["Name"] in [param_name, complete_secret]
        for param in not_found:
            # TODO: AssertionError: assert '/aws/reference/secretsmanager/9763a545_test_secret_params' in ['inexistent_param', '/aws/reference/secretsmanager/inexistent_secret']
            assert param in ["inexistent_param", secret_path + "inexistent_secret"]

    def test_get_parameters_by_path_and_filter_by_labels(self, ssm_client, create_parameter):
        prefix = f"/prefix-{short_uid()}"
        path = f"{prefix}/path"
        value = "value"
        param = create_parameter(Name=path, Value=value, Type="String")
        ssm_client.label_parameter_version(
            Name=path, ParameterVersion=param["Version"], Labels=["latest"]
        )
        list_of_params = ssm_client.get_parameters_by_path(
            Path=prefix, ParameterFilters=[{"Key": "Label", "Values": ["latest"]}]
        )
        assert len(list_of_params["Parameters"]) == 1
        found_param = list_of_params["Parameters"][0]
        assert path == found_param["Name"]
        assert found_param["ARN"]
        assert found_param["Type"] == "String"
        assert found_param["Value"] == "value"
