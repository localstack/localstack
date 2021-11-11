import pytest

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestSSM:
    def test_describe_parameters(self, ssm_client):
        response = ssm_client.describe_parameters()
        assert "Parameters" in response
        assert isinstance(response["Parameters"], list)

    def test_put_parameters(self, ssm_client):
        ssm_client.put_parameter(
            Name="test_put",
            Description="test",
            Value="123",
            Type="String",
        )

        self._assert("test_put", "test_put", ssm_client)
        self._assert("/test_put", "test_put", ssm_client)

    def test_hierarchical_parameter(self, ssm_client):
        ssm_client.put_parameter(
            Name="/a/b/c",
            Value="123",
            Type="String",
        )

        self._assert("/a/b/c", "/a/b/c", ssm_client)
        self._assert("/a//b//c", "/a/b/c", ssm_client)
        self._assert("a/b//c", "/a/b/c", ssm_client)

    def test_get_secret_parameter(self, ssm_client, secretsmanager_client):
        secret_name = "test_secret"
        secretsmanager_client.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        result = ssm_client.get_parameter(
            Name="/aws/reference/secretsmanager/{0}".format(secret_name)
        )

        assert "/aws/reference/secretsmanager/{0}".format(secret_name) == result.get(
            "Parameter"
        ).get("Name")
        assert "my_secret" == result.get("Parameter").get("Value")

        source_result = result.get("Parameter").get("SourceResult")
        assert source_result is not None, "SourceResult should be present"
        assert type(source_result) is str, "SourceResult should be a string"

    def test_get_inexistent_secret(self, ssm_client):
        with pytest.raises(ssm_client.exceptions.ParameterNotFound):
            ssm_client.get_parameter(Name="/aws/reference/secretsmanager/inexistent")

    def test_get_parameters_and_secrets(self, ssm_client):
        ssm_client = aws_stack.connect_to_service("ssm")
        sec_client = aws_stack.connect_to_service("secretsmanager")
        secret_path = "/aws/reference/secretsmanager/"

        param_name = "test_param"
        ssm_client.put_parameter(
            Name=param_name,
            Description="test",
            Value="123",
            Type="String",
        )

        secret_name = "test_secret_params"
        sec_client.create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        complete_secret = secret_path + secret_name
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

    def _assert(self, search_name, param_name, ssm_client):
        def do_assert(result):
            assert len(result) > 0
            assert param_name == result[0]["Name"]
            assert "123" == result[0]["Value"]

        response = ssm_client.get_parameter(Name=search_name)
        do_assert([response["Parameter"]])

        response = ssm_client.get_parameters(Names=[search_name])
        do_assert(response["Parameters"])

    def test_get_parameters_by_path_and_filter_by_labels(self, ssm_client):
        prefix = f"/prefix-{short_uid()}"
        path = f"{prefix}/path"
        value = "value"
        param = ssm_client.put_parameter(Name=path, Value=value, Type="String")
        ssm_client.label_parameter_version(
            Name=path, ParameterVersion=param["Version"], Labels=["latest"]
        )
        list_of_params = ssm_client.get_parameters_by_path(
            Path=prefix, ParameterFilters=[{"Key": "Label", "Values": ["latest"]}]
        )
        assert path == list_of_params["Parameters"][0]["Name"]
