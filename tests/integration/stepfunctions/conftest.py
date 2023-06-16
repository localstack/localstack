import json
import logging
from typing import Final

import pytest

from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.callbacks.callback_templates import CallbackTemplates
from tests.integration.stepfunctions.utils import await_execution_success

LOG = logging.getLogger(__name__)


@pytest.fixture
def create_iam_role_for_sfn(aws_client, cleanups, create_state_machine):
    iam_client = aws_client.iam
    stepfunctions_client = aws_client.stepfunctions

    def _create():
        role_name = f"test-sfn-role-{short_uid()}"
        policy_name = f"test-sfn-policy-{short_uid()}"
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": ["states.amazonaws.com"]},
                            "Action": ["sts:AssumeRole"],
                        }
                    ],
                }
            ),
        )
        cleanups.append(lambda: iam_client.delete_role(RoleName=role_name))
        role_arn = role["Role"]["Arn"]

        policy = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["*"],
                            "Resource": ["*"],
                        }
                    ],
                }
            ),
        )
        cleanups.append(lambda: iam_client.delete_policy(PolicyArn=policy["Policy"]["Arn"]))
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy["Policy"]["Arn"])
        cleanups.append(
            lambda: iam_client.detach_role_policy(
                RoleName=role_name, PolicyArn=policy["Policy"]["Arn"]
            )
        )

        def _wait_sfn_can_assume_role():
            sm_name = f"test-wait-sfn-can-assume-role-{short_uid()}"
            sm_def = {
                "Comment": "_wait_sfn_can_assume_role",
                "StartAt": "PullAssumeRole",
                "States": {
                    "PullAssumeRole": {
                        "Type": "Task",
                        "Parameters": {},
                        "Resource": "arn:aws:states:::aws-sdk:s3:listBuckets",
                        "Catch": [
                            {
                                "ErrorEquals": ["States.TaskFailed"],
                                "Next": "WaitAndPull",
                            }
                        ],
                        "End": True,
                    },
                    "WaitAndPull": {"Type": "Wait", "Seconds": 5, "Next": "PullAssumeRole"},
                },
            }
            creation_resp = create_state_machine(
                name=sm_name, definition=json.dumps(sm_def), roleArn=role_arn
            )
            state_machine_arn = creation_resp["stateMachineArn"]

            exec_resp = stepfunctions_client.start_execution(
                stateMachineArn=state_machine_arn, input="{}"
            )
            execution_arn = exec_resp["executionArn"]

            await_execution_success(
                stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
            )

            stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)

        _wait_sfn_can_assume_role()

        return role_arn

    return _create


@pytest.fixture
def create_state_machine(aws_client):
    _state_machine_arns: Final[list[str]] = list()

    def _create_state_machine(**kwargs):
        create_output = aws_client.stepfunctions.create_state_machine(**kwargs)
        create_output_arn = create_output["stateMachineArn"]
        _state_machine_arns.append(create_output_arn)
        return create_output

    yield _create_state_machine

    for state_machine_arn in _state_machine_arns:
        try:
            aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn)
        except Exception:
            LOG.debug(f"Unable to delete state machine '{state_machine_arn}' during cleanup.")


@pytest.fixture
def sqs_send_task_success_state_machine(aws_client, create_state_machine, create_iam_role_for_sfn):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_iam_role_for_sfn()
        sm_name: str = f"sqs_send_task_success_state_machine_{short_uid()}"
        template = CallbackTemplates.load_sfn_template(CallbackTemplates.SQS_SUCCESS_ON_TASK_TOKEN)
        definition = json.dumps(template)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({"QueueUrl": sqs_queue_url, "Iterator": {"Count": 300}}),
        )

    return _create_state_machine
