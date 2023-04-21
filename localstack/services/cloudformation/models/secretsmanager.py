import json
import logging
import random
import string

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import (
    REF_ARN_ATTRS,
    REF_ID_ATTRS,
    GenericBaseModel,
)
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import select_attributes

LOG = logging.getLogger(__name__)


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::Secret"

    def get_physical_resource_id(self, attribute, **kwargs):
        return self.props.get("ARN")

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in (REF_ARN_ATTRS + REF_ID_ATTRS):
            return self.get_physical_resource_id(attribute_name)
        return super(SecretsManagerSecret, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get("Name") or self.logical_resource_id
        result = aws_stack.connect_to_service("secretsmanager").describe_secret(
            SecretId=secret_name
        )
        return result

    @staticmethod
    def generate_secret_value(
        length: int,
        excl_lower: bool,
        excl_upper: bool,
        excl_chars: str,
        excl_numbers: bool,
        excl_punct: bool,
        incl_spaces: bool,
        req_each: bool,
    ) -> str:
        """WARN: This is NOT a secure way to generate secrets - use only for testing and not in production use cases!"""

        # TODO: add a couple of unit tests for this function ...

        punctuation = r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
        alphabet = ""
        if not excl_punct:
            alphabet += punctuation
        if not excl_upper:
            alphabet += string.ascii_uppercase
        if not excl_lower:
            alphabet += string.ascii_lowercase
        if not excl_numbers:
            alphabet += "".join([str(i) for i in list(range(10))])
        if incl_spaces:
            alphabet += " "
        if req_each:
            LOG.info("Secret generation option 'RequireEachIncludedType' not yet supported")

        for char in excl_chars:
            alphabet = alphabet.replace(char, "")

        result = [alphabet[random.randrange(len(alphabet))] for _ in range(length)]
        result = "".join(result)
        return result

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource.get("Properties", {}).get("Name")
        if not name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(params, **kwargs):
            attributes = ["Name", "Description", "KmsKeyId", "SecretString", "Tags"]
            result = select_attributes(params, attributes)
            gen_secret = params.get("GenerateSecretString")
            if gen_secret:
                excl_lower = gen_secret.get("ExcludeLowercase")
                excl_upper = gen_secret.get("ExcludeUppercase")
                excl_chars = gen_secret.get("ExcludeCharacters") or ""
                excl_numbers = gen_secret.get("ExcludeNumbers")
                excl_punct = gen_secret.get("ExcludePunctuation")
                incl_spaces = gen_secret.get("IncludeSpace")
                length = gen_secret.get("PasswordLength") or 32
                req_each = gen_secret.get("RequireEachIncludedType")
                secret_value = cls.generate_secret_value(
                    length=length,
                    excl_lower=excl_lower,
                    excl_upper=excl_upper,
                    excl_punct=excl_punct,
                    incl_spaces=incl_spaces,
                    excl_chars=excl_chars,
                    excl_numbers=excl_numbers,
                    req_each=req_each,
                )
                template = gen_secret.get("SecretStringTemplate")
                if template:
                    gen_key = gen_secret.get("GenerateStringKey") or "secret"
                    template = json.loads(template)
                    template[gen_key] = secret_value
                    secret_value = json.dumps(template)
                result["SecretString"] = secret_value
            return result

        return {
            "create": {
                "function": "create_secret",
                "parameters": _create_params,
            },
            "delete": {"function": "delete_secret", "parameters": {"SecretId": "Name"}},
        }


class SecretsManagerSecretTargetAttachment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::SecretTargetAttachment"

    def fetch_state(self, stack_name, resources):
        if not self.physical_resource_id:
            return None
        secretsmanager_client = connect_to().secretsmanager
        secret_id = self.props["SecretId"]
        secret = secretsmanager_client.get_secret_value(SecretId=secret_id)["SecretString"]
        try:
            secret = json.loads(secret)
        except json.JSONDecodeError:
            LOG.debug("Error decoding secret string %s", secret)
        if "engine" in secret:
            return secret

    @staticmethod
    def get_deploy_templates():
        def create_secret_target_attachment(resource_id, resources, *args, **kwargs):
            LOG.debug("Creating secret target attachment")
            resource = resources[resource_id]
            params = resource["Properties"]
            secret_id = params["SecretId"]
            target_id = params["TargetId"]
            target_type = params["TargetType"]
            clients = connect_to()
            secretsmanager_client = clients.secretsmanager
            rds_client = clients.rds
            old_secret = secretsmanager_client.get_secret_value(SecretId=secret_id)["SecretString"]
            try:
                old_secret = json.loads(old_secret)
            except json.JSONDecodeError:
                LOG.debug("Error decoding secret string %s", old_secret)
            if target_type == "AWS::RDS::DBInstance":
                instances = rds_client.describe_db_instances(DBInstanceIdentifier=target_id)[
                    "DBInstances"
                ]
                if not instances:
                    LOG.warning("Could not find db instance %s", target_id)
                    return {}
                instance = instances[0]
                # add keys to match https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_json_structure.html
                old_secret["host"] = instance["Endpoint"]["Address"]
                old_secret["port"] = instance["Endpoint"]["Port"]
                old_secret["dbname"] = instance["DBName"]
                old_secret["engine"] = instance["Engine"]
                return secretsmanager_client.put_secret_value(
                    SecretId=secret_id, SecretString=json.dumps(old_secret)
                )

        def _store_arn(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["ARN"]

        return {
            "create": {
                "function": create_secret_target_attachment,
                "result_handler": _store_arn,
            },
        }


class SecretsManagerRotationSchedule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::RotationSchedule"

    def get_physical_resource_id(self, attribute, **kwargs):
        return arns.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerResourcePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::ResourcePolicy"

    def get_physical_resource_id(self, attribute, **kwargs):
        return arns.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        secret_id = self.props.get("SecretId")
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
