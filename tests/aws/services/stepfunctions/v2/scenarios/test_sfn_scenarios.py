import json
import os.path
from pathlib import Path
from typing import Any, TypedDict

from localstack.aws.api.stepfunctions import ExecutionStatus
from localstack.testing.pytest import markers
from localstack.utils.sync import wait_until

THIS_FOLDER = Path(os.path.dirname(__file__))


class RunConfig(TypedDict):
    name: str
    input: Any
    terminal_state: ExecutionStatus | None


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ],
)
class TestFundamental:
    @staticmethod
    def _record_execution(
        stepfunctions_client, sfn_snapshot, statemachine_arn, run_config: RunConfig
    ):
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
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.regex(execution_id, f"<execution-id-{name}>")
        )
        sfn_snapshot.match(f"{name}__start_execution_result", start_execution_result)

        def execution_done():
            # wait until execution is successful (or a different terminal state)
            return (
                stepfunctions_client.describe_execution(executionArn=execution_arn)["status"]
                != ExecutionStatus.RUNNING
            )

        wait_until(execution_done)
        describe_ex_done = stepfunctions_client.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match(f"{name}__describe_ex_done", describe_ex_done)
        execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match(f"{name}__execution_history", execution_history)

        assert_state = run_config.get("terminal_state")
        if assert_state:
            assert describe_ex_done["status"] == assert_state

    @markers.aws.validated
    def test_path_based_on_data(self, deploy_cfn_template, sfn_snapshot, aws_client):
        """
        Based on the "path-based-on-data" sample workflow on serverlessland.com

        choice state with 3 paths
        1. input "type" is not "Private"
        2. value is >= 20 and < 30
        3. default path
        """
        deployment = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/path-based-on-data.yaml")
        )
        statemachine_arn = deployment.outputs["StateMachineArn"]
        statemachine_name = deployment.outputs["StateMachineName"]
        role_name = deployment.outputs["RoleName"]
        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(role_name, "<role-name>"))
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.regex(statemachine_name, "<state-machine-name>")
        )

        describe_statemachine = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=statemachine_arn
        )
        sfn_snapshot.match("describe_statemachine", describe_statemachine)

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
            self._record_execution(
                aws_client.stepfunctions, sfn_snapshot, statemachine_arn, run_config
            )

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..taskFailedEventDetails.resource",
            "$..taskFailedEventDetails.resourceType",
            "$..taskSubmittedEventDetails.output",
            "$..previousEventId",
            "$..MessageId",
        ],
    )
    @markers.aws.validated
    def test_wait_for_callback(self, deploy_cfn_template, sfn_snapshot, aws_client):
        """
        Based on the "wait-for-callback" sample workflow on serverlessland.com
        """
        deployment = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/wait-for-callback.yaml"),
            max_wait=240,
        )
        statemachine_arn = deployment.outputs["StateMachineArn"]
        statemachine_name = deployment.outputs["StateMachineName"]
        role_name = deployment.outputs["RoleName"]

        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(role_name, "<role-name>"))
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.regex(statemachine_name, "<state-machine-name>")
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.key_value("QueueUrl"), priority=-1)
        sfn_snapshot.add_transformer(sfn_snapshot.transform.key_value("TaskToken"))
        sfn_snapshot.add_transformer(sfn_snapshot.transform.key_value("MD5OfMessageBody"))
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value(
                "Date", value_replacement="<date>", reference_replacement=False
            )
        )

        describe_statemachine = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=statemachine_arn
        )
        sfn_snapshot.match("describe_statemachine", describe_statemachine)

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
            self._record_execution(
                aws_client.stepfunctions, sfn_snapshot, statemachine_arn, run_config
            )

    @markers.snapshot.skip_snapshot_verify(
        paths=["$..content-type"],  # FIXME: v2 includes extra content-type fields in Header fields.
    )
    @markers.aws.validated
    def test_step_functions_calling_api_gateway(
        self, deploy_cfn_template, sfn_snapshot, aws_client
    ):
        """
        Based on the "step-functions-calling-api-gateway" sample workflow on serverlessland.com
        """
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                THIS_FOLDER, "templates/step-functions-calling-api-gateway.yaml"
            ),
            max_wait=240,
        )
        statemachine_arn = deployment.outputs["StateMachineArn"]
        statemachine_name = deployment.outputs["StateMachineName"]
        role_name = deployment.outputs["RoleName"]

        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(role_name, "<role-name>"))
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.regex(statemachine_name, "<state-machine-name>")
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("X-Amz-Cf-Pop", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("X-Amz-Cf-Id", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("X-Amzn-Trace-Id", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("x-amz-apigw-id", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("x-amzn-RequestId", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("Date", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(
            sfn_snapshot.transform.key_value("Via", reference_replacement=False)
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.key_value("ApiEndpoint"), priority=-1)

        describe_statemachine = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=statemachine_arn
        )
        sfn_snapshot.match("describe_statemachine", describe_statemachine)

        run_configs = [
            {
                "name": "success",
                "input": {"fail": True},
                "terminal_state": ExecutionStatus.FAILED,
            },
            {
                "name": "failure",
                "input": {"fail": False},
                "terminal_state": ExecutionStatus.SUCCEEDED,
            },
        ]

        for run_config in run_configs:
            self._record_execution(
                aws_client.stepfunctions, sfn_snapshot, statemachine_arn, run_config
            )
