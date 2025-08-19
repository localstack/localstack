import json
import os

import aws_cdk as cdk
import botocore.exceptions
import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Tags", "$..VersionIdsToStages"])
def test_cfn_secretsmanager_gen_secret(deploy_cfn_template, aws_client, snapshot):
    secret_name = f"dev/db/pass-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/secretsmanager_secret.yml"
        ),
        parameters={"SecretName": secret_name},
    )

    secret = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
    snapshot.match("secret", secret)
    snapshot.add_transformer(snapshot.transform.regex(rf"{secret_name}-\w+", "<secret-id>"))
    snapshot.add_transformer(snapshot.transform.key_value("Name"))

    # assert that secret has been generated and added to the result template JSON
    secret_value = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)["SecretString"]
    secret_json = json.loads(secret_value)
    assert "password" in secret_json
    assert len(secret_json["password"]) == 30


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Tags", "$..VersionIdsToStages"])
def test_cfn_handle_secretsmanager_secret(deploy_cfn_template, aws_client, snapshot):
    secret_name = f"secret-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/secretsmanager_secret.yml"
        ),
        parameters={"SecretName": secret_name},
    )

    rs = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
    snapshot.match("secret", rs)
    snapshot.add_transformer(snapshot.transform.regex(rf"{secret_name}-\w+", "<secret-id>"))
    snapshot.add_transformer(snapshot.transform.key_value("Name"))

    stack.destroy()

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.secretsmanager.describe_secret(SecretId=secret_name)

    snapshot.match("exception", ex.value.response)


@markers.aws.validated
@pytest.mark.parametrize("block_public_policy", ["true", "default"])
def test_cfn_secret_policy(deploy_cfn_template, block_public_policy, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/secretsmanager_secret_policy.yml"
        ),
        parameters={"BlockPublicPolicy": block_public_policy},
    )
    secret_id = stack.outputs["SecretId"]

    snapshot.match("outputs", stack.outputs)
    secret_name = stack.outputs["SecretId"].split(":")[-1]
    snapshot.add_transformer(snapshot.transform.regex(secret_name, "<secret-name>"))

    res = aws_client.secretsmanager.get_resource_policy(SecretId=secret_id)
    snapshot.match("resource_policy", res)
    snapshot.add_transformer(snapshot.transform.key_value("Name", "policy-name"))


@markers.aws.validated
def test_cdk_deployment_generates_secret_value_if_no_value_is_provided(
    aws_client, snapshot, infrastructure_setup
):
    infra = infrastructure_setup(namespace="SecretGeneration")
    stack_name = f"SecretGeneration{short_uid()}"
    stack = cdk.Stack(infra.cdk_app, stack_name=stack_name)

    secret_name = f"my_secret{short_uid()}"
    secret = cdk.aws_secretsmanager.Secret(stack, id=secret_name, secret_name=secret_name)

    cdk.CfnOutput(stack, "SecretName", value=secret.secret_name)
    cdk.CfnOutput(stack, "SecretARN", value=secret.secret_arn)

    with infra.provisioner() as prov:
        outputs = prov.get_stack_outputs(stack_name=stack_name)

        secret_name = outputs["SecretName"]
        secret_arn = outputs["SecretARN"]

        response = aws_client.secretsmanager.get_secret_value(SecretId=secret_name)

        snapshot.add_transformer(
            snapshot.transform.key_value("SecretString", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.regex(secret_arn, "<secret_arn>"))
        snapshot.add_transformer(snapshot.transform.regex(secret_name, "<secret_name>"))

        snapshot.match("generated_key", response)
