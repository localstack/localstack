import json
import re

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


def test_cfn_secretsmanager_gen_secret(cfn_client, secretsmanager_client, deploy_cfn_template):
    stack = deploy_cfn_template(template=TEMPLATE_GENERATE_SECRET)

    secret = secretsmanager_client.describe_secret(SecretId="/dev/db/pass")
    assert "/dev/db/pass" == secret["Name"]
    assert "secret:/dev/db/pass" in secret["ARN"]

    # assert that secret has been generated and added to the result template JSON
    secret_value = secretsmanager_client.get_secret_value(SecretId="/dev/db/pass")["SecretString"]
    secret_json = json.loads(secret_value)
    assert "password" in secret_json
    assert len(secret_json["password"]) == 30

    # assert that the Ref properly returns the secret ARN
    assert len(stack.outputs) == 1

    output_secret_arn = stack.outputs["SecretARN"]
    assert output_secret_arn == secret["ARN"]
    assert re.match(r".*%s-[a-zA-Z0-9]+" % SECRET_NAME, output_secret_arn)


def test_cfn_handle_secretsmanager_secret(secretsmanager_client, deploy_cfn_template, cfn_client):
    secret_name = f"secret-{short_uid()}"
    stack = deploy_cfn_template(template=TEST_TEMPLATE_11, parameters={"SecretName": secret_name})

    rs = secretsmanager_client.describe_secret(SecretId=secret_name)
    assert rs["Name"] == secret_name
    assert "DeletedDate" not in rs

    cfn_client.delete_stack(StackName=stack.stack_name)
    assert wait_until(
        lambda: cfn_client.describe_stacks(StackName=stack.stack_id)["Stacks"][0]["StackStatus"]
        == "DELETE_COMPLETE"
    )

    rs = secretsmanager_client.describe_secret(SecretId=secret_name)
    assert "DeletedDate" in rs
