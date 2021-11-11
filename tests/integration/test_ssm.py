import pytest

from localstack.utils.common import short_uid


@pytest.fixture(scope="class")
def create_parameter(ssm_client):
    params = []

    def _create_parameter(**kwargs):
        params.append(kwargs["Name"])
        return ssm_client.put_parameter(**kwargs)

    yield _create_parameter

    for param in params:
        ssm_client.delete_parameter(Name=param)


def _assert(search_name, param_name, ssm_client):
    def do_assert(result):
        assert len(result) > 0
        assert param_name == result[0]["Name"]
        assert "123" == result[0]["Value"]

    response = ssm_client.get_parameter(Name=search_name)
    do_assert([response["Parameter"]])

    response = ssm_client.get_parameters(Names=[search_name])
    do_assert(response["Parameters"])


class TestSSM:
    def test_describe_parameters(self, ssm_client):
        response = ssm_client.describe_parameters()
        assert "Parameters" in response
        assert isinstance(response["Parameters"], list)

    def test_put_parameters(self, ssm_client):
        param_name = f"param-{short_uid()}"
        ssm_client.put_parameter(
            Name=param_name,
            Description="test",
            Value="123",
            Type="String",
        )

        _assert(param_name, param_name, ssm_client)
        _assert(f"/{param_name}", param_name, ssm_client)

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

    def test_get_secret_parameter(self, ssm_client, secretsmanager_client):
        secret_name = f"test_secret-{short_uid()}"
        secretsmanager_client.create_secret(
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

    def test_get_inexistent_secret(self, ssm_client):
        with pytest.raises(ssm_client.exceptions.ParameterNotFound):
            ssm_client.get_parameter(Name="/aws/reference/secretsmanager/inexistent")

    def test_get_parameters_and_secrets(self, ssm_client, secretsmanager_client, create_parameter):
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

        secretsmanager_client.create_secret(
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
