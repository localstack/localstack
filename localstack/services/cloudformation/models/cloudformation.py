import logging
import uuid

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.utils.aws import arns

LOG = logging.getLogger(__name__)


class CloudFormationStack(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Stack"

    def fetch_state(self, stack_name, resources):
        client = connect_to().cloudformation
        child_stack_name = self.props["StackName"]
        result = client.describe_stacks(StackName=child_stack_name)
        result = (result.get("Stacks") or [None])[0]
        return result

    def get_cfn_attribute(self, attribute_name: str):
        if attribute_name.startswith("Outputs."):
            parts = attribute_name.split(".")
            if len(parts) > 2:
                raise Exception(
                    f"Too many parts for stack output reference found: {attribute_name=}"
                )
            output_key = parts[1]
            if "Outputs" not in self.props:
                return None
            candidates = [
                o["OutputValue"] for o in self.props["Outputs"] if o["OutputKey"] == output_key
            ]
            if len(candidates) == 1:
                return candidates[0]
            else:
                raise Exception(f"Too many output values found for key {output_key=}")

        return super(CloudFormationStack, self).get_cfn_attribute(attribute_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("StackName")
        if not role_name:
            resource["Properties"]["StackName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def get_nested_stack_params(
            properties: dict, logical_resource_id: str, resource: dict, stack_name: str
        ):
            nested_stack_name = properties["StackName"]
            stack_parameters = properties.get("Parameters", {})
            stack_parameters = [
                {
                    "ParameterKey": k,
                    "ParameterValue": str(v).lower() if isinstance(v, bool) else str(v),
                }
                for k, v in stack_parameters.items()
            ]
            result = {
                "StackName": nested_stack_name,
                "TemplateURL": properties.get("TemplateURL"),
                "Parameters": stack_parameters,
            }
            return result

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            resource["PhysicalResourceId"] = result["StackId"]
            connect_to().cloudformation.get_waiter("stack_create_complete").wait(
                StackName=result["StackId"]
            )
            # set outputs
            stack_details = connect_to().cloudformation.describe_stacks(
                StackName=result["StackId"]
            )["Stacks"][0]
            if "Outputs" in stack_details:
                resource["Properties"]["Outputs"] = stack_details["Outputs"]

        return {
            "create": {
                "function": "create_stack",
                "parameters": get_nested_stack_params,
                "result_handler": _handle_result,
            }
        }


class CloudFormationMacro(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Macro"

    def fetch_state(self, stack_name, resources):
        return get_cloudformation_store().macros.get(self.props.get("Name"))

    @classmethod
    def get_deploy_templates(cls):
        def _store_macro(logical_resource_id: str, resource: dict, stack_name: str):
            properties = resource["Properties"]
            name = properties["Name"]
            get_cloudformation_store().macros[name] = properties

        def _delete_macro(logical_resource_id: str, resource: dict, stack_name: str):
            properties = resource["Properties"]
            name = properties["Name"]
            get_cloudformation_store().macros.pop(name)

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]

        return {
            "create": {
                "function": _store_macro,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": _delete_macro,
            },
        }


def generate_waitcondition_url(stack_name: str) -> str:
    client = connect_to().s3
    region = client.meta.region_name

    bucket = f"cloudformation-waitcondition-{region}"
    key = arns.cloudformation_stack_arn(stack_name=stack_name)

    return connect_to().s3.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": key}
    )


class CloudFormationWaitConditionHandle(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::CloudFormation::WaitConditionHandle"

    def fetch_state(self, stack_name, resources):
        if self.physical_resource_id is not None:
            return {"deployed": True}

    @staticmethod
    def get_deploy_templates():
        def _create(logical_resource_id: str, resource: dict, stack_name: str) -> dict:
            # no resources to create as such, but the physical resource id needs the stack name
            return {"stack_name": stack_name}

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            waitcondition_url = generate_waitcondition_url(
                stack_name=result["stack_name"],
            )
            resource["PhysicalResourceId"] = waitcondition_url

        return {
            "create": {
                "function": _create,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": lambda *args, **kwargs: {},
            },
        }


class CloudFormationWaitCondition(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::CloudFormation::WaitCondition"

    def fetch_state(self, stack_name, resources):
        if self.physical_resource_id is not None:
            return {"deployed": True}

    @staticmethod
    def get_deploy_templates():
        def _create(logical_resource_id: str, resource: dict, stack_name: str) -> dict:
            # no resources to create, but the physical resource id requires the stack name
            return {"stack_name": stack_name}

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            stack_arn = arns.cloudformation_stack_arn(result["stack_name"])
            resource["PhysicalResourceId"] = f"{stack_arn}/{uuid.uuid4()}/{logical_resource_id}"

        return {
            "create": {
                "function": _create,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": lambda *args, **kwargs: {},
            },
        }
