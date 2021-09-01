import json

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until

TEMPLATE_GENERATE_SECRET = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Secret:
    Type: 'AWS::SecretsManager::Secret'
    Properties:
      Description: Aurora Password
      Name: /dev/db/pass
      GenerateSecretString:
        SecretStringTemplate: !Sub '{"username": "${Username}"}'
        GenerateStringKey: "password"
        PasswordLength: 30
        IncludeSpace: false
        ExcludePunctuation: true
"""


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
    finally:
        cleanup_stacks([stack_id])
