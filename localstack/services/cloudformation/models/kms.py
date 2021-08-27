from localstack.services.cloudformation.service_models import REF_ID_ATTRS, GenericBaseModel
from localstack.utils.aws import aws_stack


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
                    # chain the 'PhysicalResourceId' gets overwritten with None, hence setting it here
                    self.resource_json["PhysicalResourceId"] = physical_res_id
                    break
        if not physical_res_id:
            return
        return client.describe_key(KeyId=physical_res_id)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute in REF_ID_ATTRS:
            return self.physical_resource_id
        return self.physical_resource_id and aws_stack.kms_key_arn(self.physical_resource_id)

    @staticmethod
    def get_deploy_templates():
        def create_params(params, **kwargs):
            return {
                "Policy": params.get("KeyPolicy"),
                "Tags": [
                    {"TagKey": tag["Key"], "TagValue": tag["Value"]}
                    for tag in params.get("Tags", [])
                ],
            }

        return {
            "create": {"function": "create_key", "parameters": create_params},
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
