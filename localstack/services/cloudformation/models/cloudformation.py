import logging

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.utils.aws import arns, aws_stack

LOG = logging.getLogger(__name__)


class CloudFormationStack(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Stack"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("StackId")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("cloudformation")
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
        def get_nested_stack_params(params, **kwargs):
            nested_stack_name = params["StackName"]
            stack_params = params.get("Parameters", {})
            stack_params = [
                {
                    "ParameterKey": k,
                    "ParameterValue": str(v).lower() if isinstance(v, bool) else str(v),
                }
                for k, v in stack_params.items()
            ]
            result = {
                "StackName": nested_stack_name,
                "TemplateURL": params.get("TemplateURL"),
                "Parameters": stack_params,
                # "Outputs":
            }
            return result

        def result_handler(result, *args, **kwargs):
            connect_to().cloudformation.get_waiter("stack_create_complete").wait(
                StackName=result["StackId"]
            )

        return {
            "create": {
                "function": "create_stack",
                "parameters": get_nested_stack_params,
                "result_handler": result_handler,
            }
        }


class CloudFormationMacro(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Macro"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name")

    def fetch_state(self, stack_name, resources):
        return get_cloudformation_store().macros.get(self.props.get("Name"))

    @classmethod
    def get_deploy_templates(cls):
        def _store_macro(resource_id, resources, resource_type, func, stack_name):
            resource = resources[resource_id]
            properties = resource["Properties"]
            name = properties["Name"]
            get_cloudformation_store().macros[name] = properties

        def _delete_macro(resource_id, resources, resource_type, func, stack_name):
            resource = resources[resource_id]
            properties = resource["Properties"]
            name = properties["Name"]
            get_cloudformation_store().macros.pop(name)

        return {
            "create": {
                "function": _store_macro,
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
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::WaitConditionHandle"

    @staticmethod
    def get_deploy_templates():
        def _create(resource_id, resources, resource_type, func, stack_name) -> dict:
            # no resources to create as such, but the physical resource id needs the stack name
            return {"stack_name": stack_name}

        def _set_physical_resource_id(result, resource_id, resources, resource_type):
            waitcondition_url = generate_waitcondition_url(
                stack_name=result["stack_name"],
            )
            resources[resource_id]["PhysicalResourceId"] = waitcondition_url

        return {
            "create": {
                "function": _create,
                "result_handler": _set_physical_resource_id,
            },
            "delete": {
                "function": lambda *args, **kwargs: {},
            },
        }
