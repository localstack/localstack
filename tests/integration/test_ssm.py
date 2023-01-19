import json

import pytest

from localstack.utils.common import short_uid
from localstack.utils.strings import to_str


def _assert(search_name: str, param_name: str, ssm_client):
    def do_assert(result):
        assert len(result) > 0
        assert param_name == result[0]["Name"]
        assert "123" == result[0]["Value"]

    response = ssm_client.get_parameter(Name=search_name)
    do_assert([response["Parameter"]])

    response = ssm_client.get_parameters(Names=[search_name])
    do_assert(response["Parameters"])


class TestSSM:
    @pytest.mark.aws_validated
    def test_describe_parameters(self, ssm_client):
        response = ssm_client.describe_parameters()
        assert "Parameters" in response
        assert isinstance(response["Parameters"], list)

    @pytest.mark.aws_validated
    def test_put_parameters(self, ssm_client, create_parameter):
        param_name = f"param-{short_uid()}"
        create_parameter(
            Name=param_name,
            Description="test",
            Value="123",
            Type="String",
        )

        _assert(param_name, param_name, ssm_client)
        _assert(f"/{param_name}", f"/{param_name}", ssm_client)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("param_name_pattern", ["/<param>//b//c", "<param>/b/c"])
    def test_hierarchical_parameter(self, ssm_client, create_parameter, param_name_pattern):
        param_a = short_uid()
        create_parameter(
            Name=f"/{param_a}/b/c",
            Value="123",
            Type="String",
        )

        _assert(f"/{param_a}/b/c", f"/{param_a}/b/c", ssm_client)
        pname = param_name_pattern.replace("<param>", param_a)
        with pytest.raises(Exception) as exc:
            _assert(pname, f"/{param_a}/b/c", ssm_client)
        exc.match("ValidationException")
        exc.match("sub-paths divided by slash symbol")

    @pytest.mark.aws_validated
    def test_get_secret_parameter(self, ssm_client, create_secret):
        secret_name = f"test_secret-{short_uid()}"
        create_secret(
            Name=secret_name,
            SecretString="my_secret",
            Description="testing creation of secrets",
        )

        result = ssm_client.get_parameter(
            Name=f"/aws/reference/secretsmanager/{secret_name}", WithDecryption=True
        )
        assert f"/aws/reference/secretsmanager/{secret_name}" == result.get("Parameter").get("Name")
        assert "my_secret" == result.get("Parameter").get("Value")

        source_result = result.get("Parameter").get("SourceResult")
        assert source_result
        source_result = json.loads(to_str(source_result))
        assert source_result["name"] == secret_name
        assert ":secretsmanager:" in source_result["ARN"]

        # negative test for https://github.com/localstack/localstack/issues/6551
        with pytest.raises(Exception):
            ssm_client.get_parameter(Name=secret_name, WithDecryption=True)

    @pytest.mark.aws_validated
    def test_get_inexistent_secret(self, ssm_client):
        invalid_name = "/aws/reference/secretsmanager/inexistent"
        with pytest.raises(ssm_client.exceptions.ParameterNotFound) as exc:
            ssm_client.get_parameter(Name=invalid_name, WithDecryption=True)
        exc.match("ParameterNotFound")
        exc.match(f"Secret .*{invalid_name.lstrip('/')}.* not found.")

    @pytest.mark.aws_validated
    def test_get_parameters_and_secrets(self, ssm_client, create_parameter, create_secret):
        param_name = f"param-{short_uid()}"
        secret_path = "/aws/reference/secretsmanager/"
        secret_name = f"test_secret_param_{short_uid()}"
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
            ],
            WithDecryption=True,
        )
        found = response.get("Parameters")
        not_found = response.get("InvalidParameters")

        for param in found:
            assert param["Name"] in [param_name, complete_secret]
        for param in not_found:
            assert param in ["inexistent_param", secret_path + "inexistent_secret"]

    @pytest.mark.aws_validated
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

    @pytest.mark.aws_validated
    def test_get_inexistent_maintenance_window(self, ssm_client):
        invalid_name = "mw-00000000000000000"
        with pytest.raises(ssm_client.exceptions.DoesNotExistException) as exc:
            ssm_client.get_maintenance_window(WindowId=invalid_name)
        exc.match("DoesNotExistException")
        exc.match(f"Maintenance window {invalid_name} does not exist")
