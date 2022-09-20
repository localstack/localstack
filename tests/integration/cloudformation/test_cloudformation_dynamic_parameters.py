import os

import pytest as pytest

from localstack.utils.common import short_uid


def test_resolve_ssm(
    create_parameter,
    deploy_cfn_template,
):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"
    create_parameter(Name=parameter_key, Value=parameter_value, Type="String")

    result = deploy_cfn_template(
        parameters={"DynamicParameter": parameter_key},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


def test_resolve_ssm_with_version(ssm_client, cfn_client, create_parameter, deploy_cfn_template):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value_v0 = f"param-value-{short_uid()}"
    parameter_value_v1 = f"param-value-{short_uid()}"
    parameter_value_v2 = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Type="String", Value=parameter_value_v0)

    v1 = ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v1
    )
    ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v2
    )

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}:{v1['Version']}"},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value_v1


def test_resolve_ssm_secure(create_parameter, cfn_client, deploy_cfn_template):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Value=parameter_value, Type="SecureString")

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}"},
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/resolve_ssm_secure.yaml"
        ),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


@pytest.mark.parametrize(
    "template_name", ["resolve_secretsmanager_full.yaml", "resolve_secretsmanager.yaml"]
)
def test_resolve_secretsmanager(
    secretsmanager_client,
    cfn_client,
    create_secret,
    deploy_cfn_template,
    template_name,
):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_secret(Name=parameter_key, SecretString=parameter_value)

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}"},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/", template_name),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value
