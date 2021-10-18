import json
import re

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until

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
        SecretStringTemplate: !Sub '{"username": "${Username}"}'
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


def test_cfn_secretsmanager_gen_secret(
    cfn_client,
    secretsmanager_client,
    is_stack_created,
    cleanup_stacks,
):
    stack_name = f"stack-{short_uid()}"
    response = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=TEMPLATE_GENERATE_SECRET,
    )
    stack_id = response["StackId"]

    try:
        wait_until(is_stack_created(stack_id))
        secret = secretsmanager_client.describe_secret(SecretId="/dev/db/pass")
        assert "/dev/db/pass" == secret["Name"]
        assert "secret:/dev/db/pass" in secret["ARN"]

        # assert that secret has ben generated and added to the result template JSON
        value = secretsmanager_client.get_secret_value(SecretId="/dev/db/pass")
        secret = value.get("SecretString")
        secret = json.loads(secret)
        assert "password" in secret
        assert len(secret["password"]) == 30

        # assert that the Ref properly returns the secret ARN
        result = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert len(result["Outputs"]) == 1
        assert result["Outputs"][0]["OutputKey"] == "SecretARN"
        assert re.match(r".*%s-[a-zA-Z0-9]+" % SECRET_NAME, result["Outputs"][0]["OutputValue"])
    finally:
        cleanup_stacks([stack_id])
