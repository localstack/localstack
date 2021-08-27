import json

from localstack.services.cloudformation.deployment_utils import lambda_select_params
from localstack.services.cloudformation.service_models import (
    REF_ARN_ATTRS,
    REF_ID_ATTRS,
    GenericBaseModel,
)
from localstack.utils.aws import aws_stack


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::Secret"

    def get_physical_resource_id(self, attribute, **kwargs):
        props = self.props
        result = props.get("Arn") or aws_stack.secretsmanager_secret_arn(props["Name"])
        return result

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in (REF_ARN_ATTRS + REF_ID_ATTRS):
            return self.get_physical_resource_id(attribute_name)
        return super(SecretsManagerSecret, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get("Name") or self.resource_id
        secret_name = self.resolve_refs_recursively(stack_name, secret_name, resources)
        result = aws_stack.connect_to_service("secretsmanager").describe_secret(
            SecretId=secret_name
        )
        return result

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_secret",
                "parameters": lambda_select_params(
                    "Name", "Description", "KmsKeyId", "SecretString", "Tags"
                ),
            },
            "delete": {"function": "delete_secret", "parameters": {"SecretId": "Name"}},
        }


class SecretsManagerSecretTargetAttachment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::SecretTargetAttachment"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerRotationSchedule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::RotationSchedule"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerResourcePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::ResourcePolicy"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        secret_id = self.resolve_refs_recursively(stack_name, self.props.get("SecretId"), resources)
        result = aws_stack.connect_to_service("secretsmanager").get_resource_policy(
            SecretId=secret_id
        )
        return result

    @staticmethod
    def get_deploy_templates():
        def create_params(params, **kwargs):
            return {
                "SecretId": params["SecretId"].split(":")[-1],
                "ResourcePolicy": json.dumps(params["ResourcePolicy"]),
                "BlockPublicPolicy": params.get("BlockPublicPolicy"),
            }

        return {
            "create": {"function": "put_resource_policy", "parameters": create_params},
            "delete": {
                "function": "delete_resource_policy",
                "parameters": {"SecretId": "SecretId"},
            },
        }
