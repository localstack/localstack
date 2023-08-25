import json
import logging
import random
import string

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.common import select_attributes

LOG = logging.getLogger(__name__)


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::Secret"

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get("Name") or self.logical_resource_id
        result = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).secretsmanager.describe_secret(SecretId=secret_name)
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
            # not actually correct. Given the LogicalResourceId "MySecret",
            # an example for the generated name would be "MySecret-krxoxgcznYdq-sQNsqO"
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            attributes = ["Name", "Description", "KmsKeyId", "SecretString", "Tags"]
            result = select_attributes(properties, attributes)
            gen_secret = properties.get("GenerateSecretString")
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

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Id"] = result["ARN"]
            resource["PhysicalResourceId"] = result["ARN"]

        return {
            "create": {
                "function": "create_secret",
                "parameters": _create_params,
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_secret", "parameters": {"SecretId": "Name"}},
        }


class SecretsManagerSecretTargetAttachment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::SecretTargetAttachment"

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerRotationSchedule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::RotationSchedule"

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerResourcePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::ResourcePolicy"

    def fetch_state(self, stack_name, resources):
        secret_id = self.props.get("SecretId")
        result = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).secretsmanager.get_resource_policy(SecretId=secret_id)
        return result

    @staticmethod
    def get_deploy_templates():
        def create_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            return {
                "SecretId": properties["SecretId"],
                "ResourcePolicy": json.dumps(properties["ResourcePolicy"]),
                "BlockPublicPolicy": properties.get("BlockPublicPolicy"),
            }

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["ARN"]

        return {
            "create": {
                "function": "put_resource_policy",
                "parameters": create_params,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_resource_policy",
                "parameters": {"SecretId": "SecretId"},
            },
        }
