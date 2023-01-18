import logging

from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack

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
        # probably not the best way to wait in a blocking manner here but the current implementation requires it
        client.get_waiter("stack_create_complete").wait(StackName=child_stack_name)
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

        return {
            "create": {
                "function": "create_stack",
                "parameters": get_nested_stack_params,
            }
        }
