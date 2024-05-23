import json
import re

import aws_cdk as cdk
import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until

SECRET_NAME = "/dev/db/pass"
TEMPLATE_GENERATE_SECRET = (
    """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Secret:
    Type: 'AWS::SecretsManager::Secret'
    Properties:
      Description: Aurora Password
      Name: %s
      GenerateSecretString:
        SecretStringTemplate: '{"username": "localstack-user"}'
        GenerateStringKey: "password"
        PasswordLength: 30
        IncludeSpace: false
        ExcludePunctuation: true
Outputs:
  SecretARN:
    Value: !Ref Secret
"""
    % SECRET_NAME
)


TEST_TEMPLATE_11 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  SecretName:
    Type: String
Resources:
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Ref "SecretName"
      Tags:
        - Key: AppName
          Value: AppA
"""

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-resourcepolicy.html#aws-resource-secretsmanager-resourcepolicy--examples--Attaching_a_resource-based_policy_to_an_RDS_database_instance_secret_--yaml
TEST_TEMPLATE_SECRET_POLICY = """
Parameters:
  BlockPublicPolicy:
    Type: String
    AllowedValues:
      - "true"
      - "default"

Conditions:
  ShouldBlockPublicPolicy:
    !Equals [!Ref BlockPublicPolicy, "true"]

Resources:
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
          Description: This is a secret that I want to attach a resource-based policy to
  MySecretResourcePolicy:
    Type: AWS::SecretsManager::ResourcePolicy
    Properties:
      BlockPublicPolicy: !If [ShouldBlockPublicPolicy, True, !Ref AWS::NoValue]
      SecretId:
        Ref: MySecret
      ResourcePolicy:
        Version: '2012-10-17'
        Statement:
        - Resource: "*"
          Action: secretsmanager:ReplicateSecretToRegions
          Effect: Allow
          Principal:
            AWS:
              Fn::Sub: arn:aws:iam::${AWS::AccountId}:root
Outputs:
  SecretId:
    Value: !GetAtt MySecret.Id

  SecretPolicyArn:
    Value: !Ref MySecretResourcePolicy
"""


@markers.aws.unknown
def test_cfn_secretsmanager_gen_secret(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(template=TEMPLATE_GENERATE_SECRET)

    secret = aws_client.secretsmanager.describe_secret(SecretId="/dev/db/pass")
    assert "/dev/db/pass" == secret["Name"]
    assert "secret:/dev/db/pass" in secret["ARN"]

    # assert that secret has been generated and added to the result template JSON
    secret_value = aws_client.secretsmanager.get_secret_value(SecretId="/dev/db/pass")[
        "SecretString"
    ]
    secret_json = json.loads(secret_value)
    assert "password" in secret_json
    assert len(secret_json["password"]) == 30

    # assert that the Ref properly returns the secret ARN
    assert len(stack.outputs) == 1

    output_secret_arn = stack.outputs["SecretARN"]
    assert output_secret_arn == secret["ARN"]
    assert re.match(r".*%s-[a-zA-Z0-9]+" % SECRET_NAME, output_secret_arn)


@markers.aws.unknown
def test_cfn_handle_secretsmanager_secret(deploy_cfn_template, aws_client):
    secret_name = f"secret-{short_uid()}"
    stack = deploy_cfn_template(template=TEST_TEMPLATE_11, parameters={"SecretName": secret_name})

    rs = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
    assert rs["Name"] == secret_name
    assert "DeletedDate" not in rs

    aws_client.cloudformation.delete_stack(StackName=stack.stack_name)
    assert wait_until(
        lambda: aws_client.cloudformation.describe_stacks(StackName=stack.stack_id)["Stacks"][0][
            "StackStatus"
        ]
        == "DELETE_COMPLETE"
    )

    rs = aws_client.secretsmanager.describe_secret(SecretId=secret_name)
    assert "DeletedDate" in rs


@markers.aws.validated
@pytest.mark.parametrize("block_public_policy", ["true", "default"])
def test_cfn_secret_policy(deploy_cfn_template, block_public_policy, aws_client, snapshot):
    stack = deploy_cfn_template(
        template=TEST_TEMPLATE_SECRET_POLICY, parameters={"BlockPublicPolicy": block_public_policy}
    )
    secret_id = stack.outputs["SecretId"]

    snapshot.match("outputs", stack.outputs)
    secret_name = stack.outputs["SecretId"].split(":")[-1]
    snapshot.add_transformer(snapshot.transform.regex(secret_name, "<secret-name>"))

    # TODO: moto does not implement the `ResourcePolicy` key
    # res = aws_client.secretsmanager.get_resource_policy(SecretId=secret_id)
    # snapshot.match("resource-policy", res["ResourcePolicy"])
    aws_client.secretsmanager.get_resource_policy(SecretId=secret_id)


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

        snapshot.add_transformer(snapshot.transform.key_value("SecretString"))
        snapshot.add_transformer(snapshot.transform.regex(secret_arn, "<secret_arn>"))
        snapshot.add_transformer(snapshot.transform.regex(secret_name, "<secret_name>"))

        snapshot.match("generated_key", response)
