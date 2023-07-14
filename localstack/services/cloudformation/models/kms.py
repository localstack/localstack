import json

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns


class KMSKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Key"

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "Arn":
            return arns.kms_key_arn(self.physical_resource_id)
        return super(KMSKey, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        client = connect_to().kms
        physical_res_id = self.physical_resource_id
        props = self.props
        res_tags = props.get("Tags", [])
        if not physical_res_id:
            # TODO: find a more efficient approach for this?
            for key in client.list_keys()["Keys"]:
                details = client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                tags = client.list_resource_tags(KeyId=key["KeyId"]).get("Tags", [])
                tags = [{"Key": tag["TagKey"], "Value": tag["TagValue"]} for tag in tags]
                if (
                    tags == res_tags
                    and details.get("Description") == props.get("Description")
                    and props.get("KeyUsage") in [None, details.get("KeyUsage")]
                ):
                    physical_res_id = key["KeyId"]
                    # TODO should this be removed from here? It seems that somewhere along the execution
                    #  chain the 'PhysicalResourceId' gets overwritten with None, hence setting it here
                    self.resource_json["PhysicalResourceId"] = physical_res_id
                    break
        if not physical_res_id:
            return
        return client.describe_key(KeyId=physical_res_id)

    @classmethod
    def get_deploy_templates(cls):
        def _create(logical_resource_id: str, resource: dict, stack_name: str):
            kms_client = connect_to().kms
            resource_provider = cls(resource)
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

        def _handle_key_result(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["KeyMetadata"]["KeyId"]

        return {
            "create": [
                {"function": _create, "result_handler": _handle_key_result},
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
        aliases = connect_to().kms.list_aliases()["Aliases"]
        for alias in aliases:
            if alias["AliasName"] == self.props.get("AliasName"):
                return alias
        return None

    @staticmethod
    def get_deploy_templates():
        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
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
