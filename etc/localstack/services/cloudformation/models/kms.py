import json

from localstack.services.cloudformation.service_models import REF_ID_ATTRS, GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class KMSKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Key"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("kms")
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

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute in REF_ID_ATTRS:
            return self.physical_resource_id
        return self.physical_resource_id and aws_stack.kms_key_arn(self.physical_resource_id)

    # TODO: try to remove this workaround (ensures idempotency)
    @staticmethod
    def add_defaults(resource, stack_name: str):
        props = resource["Properties"] = resource.get("Properties", {})
        tags = props["Tags"] = props.get("Tags", [])
        existing = [t for t in tags if t["Key"] == "localstack-key-id"]
        if not existing:
            # append tags, to allow us to determine in fetch_state whether this key is already deployed
            tags.append({"Key": "localstack-key-id", "Value": short_uid()})

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name):
            kms_client = aws_stack.connect_to_service("kms")
            resource = cls(resources[resource_id])
            props = resource.props
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
            resource.resource_json["PhysicalResourceId"] = key_id

            # key is created but some fields map to separate api calls
            if props.get("EnableKeyRotation", False):
                kms_client.enable_key_rotation(KeyId=key_id)
            else:
                kms_client.disable_key_rotation(KeyId=key_id)

            if props.get("Enabled", True):
                kms_client.enable_key(KeyId=key_id)
            else:
                kms_client.disable_key(KeyId=key_id)

        return {
            "create": [
                {"function": _create},
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

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("AliasName")

    def fetch_state(self, stack_name, resources):
        kms = aws_stack.connect_to_service("kms")
        aliases = kms.list_aliases()["Aliases"]
        for alias in aliases:
            if alias["AliasName"] == self.props.get("AliasName"):
                return alias
        return None

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_alias",
                "parameters": {"AliasName": "AliasName", "TargetKeyId": "TargetKeyId"},
            },
            "delete": {
                "function": "delete_alias",
                "parameters": {"AliasName": "AliasName"},
            },
        }
