import re
from typing import Dict

from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_RESOURCE_NAME
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class SFNActivity(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::StepFunctions::Activity"

    def fetch_state(self, stack_name, resources):
        activity_arn = self.physical_resource_id
        if not activity_arn:
            return None
        client = aws_stack.connect_to_service("stepfunctions")
        result = client.describe_activity(activityArn=activity_arn)
        return result

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_activity",
                "parameters": {"name": ["Name", PLACEHOLDER_RESOURCE_NAME], "tags": "Tags"},
            },
            "delete": {
                "function": "delete_activity",
                "parameters": {"activityArn": "PhysicalResourceId"},
            },
        }


class SFNStateMachine(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::StepFunctions::StateMachine"

    def get_resource_name(self):
        return self.props.get("StateMachineName")

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("stateMachineArn")

    def fetch_state(self, stack_name, resources):
        sm_name = self.props.get("StateMachineName") or self.resource_id
        sm_name = self.resolve_refs_recursively(stack_name, sm_name, resources)
        sfn_client = aws_stack.connect_to_service("stepfunctions")
        state_machines = sfn_client.list_state_machines()["stateMachines"]
        sm_arn = [m["stateMachineArn"] for m in state_machines if m["name"] == sm_name]
        if not sm_arn:
            return None
        result = sfn_client.describe_state_machine(stateMachineArn=sm_arn[0])
        return result

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("stepfunctions")
        sm_arn = self.props.get("stateMachineArn")
        if not sm_arn:
            self.state = self.fetch_state(stack_name=stack_name, resources=resources)
            sm_arn = self.state["stateMachineArn"]
        kwargs = {
            "stateMachineArn": sm_arn,
            "definition": props["DefinitionString"],
        }
        return client.update_state_machine(**kwargs)

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(params, **kwargs):
            def _get_definition(params):
                definition_str = params.get("DefinitionString")
                substitutions = params.get("DefinitionSubstitutions")
                if substitutions is not None:
                    definition_str = _apply_substitutions(definition_str, substitutions)
                return definition_str

            return {
                "name": params.get("StateMachineName", PLACEHOLDER_RESOURCE_NAME),
                "definition": _get_definition(params),
                "roleArn": params.get("RoleArn"),
                "type": params.get("StateMachineTyp", None),
            }

        return {
            "create": {
                "function": "create_state_machine",
                "parameters": _create_params,
            },
            "delete": {
                "function": "delete_state_machine",
                "parameters": {"stateMachineArn": "PhysicalResourceId"},
            },
        }


def _apply_substitutions(definition: str, substitutions: Dict[str, str]) -> str:
    substitution_regex = re.compile("\\${[a-zA-Z0-9_]+}")  # might be a bit too strict in some cases
    tokens = substitution_regex.findall(definition)
    result = definition
    for token in tokens:
        raw_token = token[2:-1]  # strip ${ and }
        if raw_token not in substitutions.keys():
            raise
        result = result.replace(token, substitutions[raw_token])

    return result
