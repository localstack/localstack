import json

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.service_models import GenericBaseModel


class KMSKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Key"

    def fetch_state(self, stack_name, resources):
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).kms
        physical_res_id = self.physical_resource_id
        return client.describe_key(KeyId=physical_res_id)

    @classmethod
    def get_deploy_templates(cls):
        def _create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            kms_client = connect_to(aws_access_key_id=account_id, region_name=region_name).kms
            resource_provider = cls(account_id, region_name, resource)
            props = resource_provider.props
            params = {}
            if props.get("KeyPolicy"):
                params["Policy"] = json.dumps(props["KeyPolicy"])

            if props.get("Tags"):
                params["Tags"] = [
                    {"TagKey": tag["Key"], "TagValue": tag["Value"]}
                    for tag in props.get("Tags", [])
                ]

            for key in ["Description", "KeySpec", "KeyUsage"]:
                if props.get(key):
                    params[key] = props[key]

            new_key = kms_client.create_key(**params)
            key_id = new_key["KeyMetadata"]["KeyId"]

            # key is created but some fields map to separate api calls
            if props.get("EnableKeyRotation", False):
                kms_client.enable_key_rotation(KeyId=key_id)
            else:
                kms_client.disable_key_rotation(KeyId=key_id)

            if props.get("Enabled", True):
                kms_client.enable_key(KeyId=key_id)
            else:
                kms_client.disable_key(KeyId=key_id)

            return new_key

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["KeyMetadata"]["KeyId"]
            resource["Properties"]["Arn"] = result["KeyMetadata"]["Arn"]

        return {
            "create": [
                {"function": _create, "result_handler": _handle_result},
            ],
            "delete": {
                # TODO Key needs to be deleted in KMS backend
                "function": "schedule_key_deletion",
                "parameters": {"KeyId": "PhysicalResourceId"},
            },
        }


class KMSAlias(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Alias"

    def fetch_state(self, stack_name, resources):
        aliases = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).kms.list_aliases()["Aliases"]
        for alias in aliases:
            if alias["AliasName"] == self.props.get("AliasName"):
                return alias
        return None

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = resource["Properties"]["AliasName"]

        return {
            "create": {
                "function": "create_alias",
                "parameters": {"AliasName": "AliasName", "TargetKeyId": "TargetKeyId"},
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_alias",
                "parameters": {"AliasName": "AliasName"},
            },
        }
