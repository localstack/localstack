import json
import re

import pytest

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
Resources:
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
          Description: This is a secret that I want to attach a resource-based policy to
  MySecretResourcePolicy:
    Type: AWS::SecretsManager::ResourcePolicy
    Properties:
      BlockPublicPolicy: True
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


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..SecretId", "$..SecretPolicyArn"])
def test_cfn_secret_policy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(template=TEST_TEMPLATE_SECRET_POLICY)
    secret_id = stack.outputs["SecretId"]

    snapshot.match("outputs", stack.outputs)

    # TODO: moto does not implement the `ResourcePolicy` key
    # res = aws_client.secretsmanager.get_resource_policy(SecretId=secret_id)
    # snapshot.match("resource-policy", res["ResourcePolicy"])
    aws_client.secretsmanager.get_resource_policy(SecretId=secret_id)
