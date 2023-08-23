import logging
import re
from typing import Dict

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


class SFNActivity(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::StepFunctions::Activity"

    def fetch_state(self, stack_name, resources):
        activity_arn = self.physical_resource_id
        if not activity_arn:
            return None
        client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).stepfunctions
        result = client.describe_activity(activityArn=activity_arn)
        return result

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["activityArn"]
            resource["PhysicalResourceId"] = result["activityArn"]

        return {
            "create": {
                "function": "create_activity",
                "parameters": {"name": "Name", "tags": "Tags"},
                "result_handler": _handle_result,
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

    def fetch_state(self, stack_name, resources):
        sm_name = self.props.get("StateMachineName") or self.logical_resource_id
        sfn_client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).stepfunctions
        state_machines = sfn_client.list_state_machines()["stateMachines"]
        sm_arn = [m["stateMachineArn"] for m in state_machines if m["name"] == sm_name]
        if not sm_arn:
            return None
        result = sfn_client.describe_state_machine(stateMachineArn=sm_arn[0])
        return result

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).stepfunctions
        sm_arn = self.props.get("stateMachineArn")
        if not sm_arn:
            self.state = self.fetch_state(stack_name=stack_name, resources=resources)
            sm_arn = self.state["stateMachineArn"]
        kwargs = {
            "stateMachineArn": sm_arn,
            "definition": props["DefinitionString"],
        }
        return client.update_state_machine(**kwargs)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("StateMachineName")
        if not role_name:
            resource["Properties"]["StateMachineName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["stateMachineArn"]
            resource["Properties"]["Name"] = resource["Properties"]["StateMachineName"]
            # resource["Properties"]["StateMachineRevisionId"] = ?
            resource["PhysicalResourceId"] = result["stateMachineArn"]

        def _create_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            def _get_definition(properties):
                # TODO: support "Definition" parameter
                definition_str = properties.get("DefinitionString")
                s3_location = properties.get("DefinitionS3Location")
                if not definition_str and s3_location:
                    # TODO: currently not covered by tests - add a test to mimick the behavior of "sam deploy ..."
                    s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
                    LOG.debug("Fetching state machine definition from S3: %s", s3_location)
                    result = s3_client.get_object(
                        Bucket=s3_location["Bucket"], Key=s3_location["Key"]
                    )
                    definition_str = to_str(result["Body"].read())
                substitutions = properties.get("DefinitionSubstitutions")
                if substitutions is not None:
                    definition_str = _apply_substitutions(definition_str, substitutions)
                return definition_str

            return {
                "name": properties.get("StateMachineName"),
                "definition": _get_definition(properties),
                "roleArn": properties.get("RoleArn"),
                "type": properties.get("StateMachineType", None),
            }

        return {
            "create": {
                "function": "create_state_machine",
                "parameters": _create_params,
                "result_handler": _handle_result,
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
