from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class CloudFormationStack(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Stack"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("StackId")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("cloudformation")
        child_stack_name = self.props["StackName"]
        child_stack_name = self.resolve_refs_recursively(stack_name, child_stack_name, resources)
        result = client.describe_stacks(StackName=child_stack_name)
        result = (result.get("Stacks") or [None])[0]
        return result

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
            }
            return result

        return {
            "create": {
                "function": "create_stack",
                "parameters": get_nested_stack_params,
            }
        }
