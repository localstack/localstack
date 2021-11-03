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

        # assert that secret has been generated and added to the result template JSON
        secret_value = secretsmanager_client.get_secret_value(SecretId="/dev/db/pass")[
            "SecretString"
        ]
        secret_json = json.loads(secret_value)
        assert "password" in secret_json
        assert len(secret_json["password"]) == 30

        # assert that the Ref properly returns the secret ARN
        result = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert len(result["Outputs"]) == 1

        assert result["Outputs"][0]["OutputKey"] == "SecretARN"
        output_secret_arn = result["Outputs"][0]["OutputValue"]
        assert output_secret_arn == secret["ARN"]
        assert re.match(r".*%s-[a-zA-Z0-9]+" % SECRET_NAME, output_secret_arn)
    finally:
        cleanup_stacks([stack_id])
