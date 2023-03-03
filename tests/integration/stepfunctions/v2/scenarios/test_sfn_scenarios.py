import json
import os.path
from pathlib import Path
from typing import Any, TypedDict

import pytest

from localstack.aws.api.stepfunctions import ExecutionStatus
from localstack.utils.sync import wait_until
from tests.integration.stepfunctions.utils import is_old_provider

THIS_FOLDER = Path(os.path.dirname(__file__))


class RunConfig(TypedDict):
    name: str
    input: Any
    terminal_state: ExecutionStatus | None


@pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..tracingConfiguration"])
class TestFundamental:
    @staticmethod
    def _record_execution(stepfunctions_client, snapshot, statemachine_arn, run_config: RunConfig):
        """
        This pattern is used throughout all stepfunctions scenario tests.
        It starts a single state machine execution and snapshots all related information for the execution.
        Make sure the "name" in the run_config is unique in the run.
        """
        name = run_config["name"]
        start_execution_result = stepfunctions_client.start_execution(
            stateMachineArn=statemachine_arn, input=json.dumps(run_config["input"])
        )
        execution_arn = start_execution_result["executionArn"]
        execution_id = execution_arn.split(":")[-1]
        snapshot.add_transformer(snapshot.transform.regex(execution_id, f"<execution-id-{name}>"))
        snapshot.match(f"{name}__start_execution_result", start_execution_result)

        def execution_done():
            # wait until execution is successful (or a different terminal state)
            return (
                stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
                != ExecutionStatus.RUNNING
            )

        wait_until(execution_done)
        describe_ex_done = stepfunctions_client.describe_execution(executionArn=execution_arn)
        snapshot.match(f"{name}__describe_ex_done", describe_ex_done)
        execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        snapshot.match(f"{name}__execution_history", execution_history)

        assert_state = run_config.get("terminal_state")
        if assert_state:
            assert describe_ex_done["status"] == assert_state

    @pytest.mark.aws_validated
    def test_path_based_on_data(self, deploy_cfn_template, stepfunctions_client, snapshot):
        """
        Based on the "path-based-on-data" sample workflow on serverlessland.com

        choice state with 3 paths
        1. input "type" is not "Private"
        2. value is >= 20 and < 30
        3. default path
        """
        deployment = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "./templates/path-based-on-data.yaml")
        )
        statemachine_arn = deployment.outputs["StateMachineArn"]
        statemachine_name = deployment.outputs["StateMachineName"]
        role_name = deployment.outputs["RoleName"]
        snapshot.add_transformer(snapshot.transform.regex(role_name, "<role-name>"))
        snapshot.add_transformer(
            snapshot.transform.regex(statemachine_name, "<state-machine-name>")
        )

        describe_statemachine = stepfunctions_client.describe_state_machine(
            stateMachineArn=statemachine_arn
        )
        snapshot.match("describe_statemachine", describe_statemachine)

        run_configs = [
            {
                "name": "first_path",
                "input": {"type": "Public", "value": 3},
                "terminal_state": ExecutionStatus.SUCCEEDED,
            },
            {
                "name": "second_path",
                "input": {"type": "Private", "value": 25},
                "terminal_state": ExecutionStatus.SUCCEEDED,
            },
            {
                "name": "default_path",
                "input": {"type": "Private", "value": 3},
                "terminal_state": ExecutionStatus.SUCCEEDED,
            },
        ]

        for run_config in run_configs:
            self._record_execution(stepfunctions_client, snapshot, statemachine_arn, run_config)

    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..taskFailedEventDetails.resource",
            "$..taskFailedEventDetails.resourceType",
            "$..taskSubmittedEventDetails.output",
            "$..previousEventId",
        ],
    )
    @pytest.mark.aws_validated
    def test_wait_for_callback(self, deploy_cfn_template, stepfunctions_client, snapshot):
        """
        Based on the "wait-for-callback" sample workflow on serverlessland.com
        """
        deployment = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "./templates/wait-for-callback.yaml"),
            max_wait=240,
        )
        statemachine_arn = deployment.outputs["StateMachineArn"]
        statemachine_name = deployment.outputs["StateMachineName"]
        role_name = deployment.outputs["RoleName"]

        snapshot.add_transformer(snapshot.transform.regex(role_name, "<role-name>"))
        snapshot.add_transformer(
            snapshot.transform.regex(statemachine_name, "<state-machine-name>")
        )
        snapshot.add_transformer(snapshot.transform.key_value("QueueUrl"), priority=-1)
        snapshot.add_transformer(snapshot.transform.key_value("TaskToken"))
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfMessageBody"))
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "Date", value_replacement="<date>", reference_replacement=False
            )
        )

        describe_statemachine = stepfunctions_client.describe_state_machine(
            stateMachineArn=statemachine_arn
        )
        snapshot.match("describe_statemachine", describe_statemachine)

        run_configs = [
            {
                "name": "success",
                "input": {"shouldfail": "no"},
                "terminal_state": ExecutionStatus.SUCCEEDED,
            },
            {
                "name": "failure",
                "input": {"shouldfail": "yes"},
                "terminal_state": ExecutionStatus.FAILED,
            },
        ]

        for run_config in run_configs:
            self._record_execution(stepfunctions_client, snapshot, statemachine_arn, run_config)

    def test_batch_lambda_cdk(self, deploy_cfn_template):
        """
        Based on the "batch-lambda-cdk" sample workflow on serverlessland.com
        """
        raise Exception("TODO")

    def test_request_response_cdk(self, deploy_cfn_template):
        """
        Based on the "request-response-cdk" sample workflow on serverlessland.com
        """
        raise Exception("TODO")

    def test_step_functions_calling_api_gateway(self, deploy_cfn_template):
        """
        Based on the "step-functions-calling-api-gateway" sample workflow on serverlessland.com
        """
        raise Exception("TODO")
