import json
import logging
from typing import Final

import pytest
from jsonpath_ng.ext import parse
from localstack_snapshot.snapshots.transformer import TransformContext

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates,
)
from tests.aws.services.stepfunctions.utils import await_execution_success

LOG = logging.getLogger(__name__)


@pytest.fixture
def sfn_snapshot(snapshot):
    snapshot.add_transformers_list(snapshot.transform.stepfunctions_api())
    return snapshot


class SfnNoneRecursiveParallelTransformer:
    """
    Normalises a sublist of events triggered in by a Parallel state to be order-independent.
    """

    def __init__(self, events_jsonpath: str = "$..events"):
        self.events_jsonpath: str = events_jsonpath

    @staticmethod
    def _normalise_events(events: list[dict]) -> None:
        start_idx = None
        sublist = list()
        in_sublist = False
        for i, event in enumerate(events):
            event_type = event.get("type")
            if event_type is None:
                LOG.debug(f"No 'type' in event item '{event}'.")
                in_sublist = False

            elif event_type in {
                None,
                HistoryEventType.ParallelStateSucceeded,
                HistoryEventType.ParallelStateAborted,
                HistoryEventType.ParallelStateExited,
                HistoryEventType.ParallelStateFailed,
            }:
                events[start_idx:i] = sorted(sublist, key=lambda e: to_json_str(e))
                in_sublist = False
            elif event_type == HistoryEventType.ParallelStateStarted:
                in_sublist = True
                sublist = []
                start_idx = i + 1
            elif in_sublist:
                event["id"] = (0,)
                event["previousEventId"] = 0
                sublist.append(event)

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse("$..events")
        events = pattern.find(input_data)
        if not events:
            LOG.debug(f"No Stepfunctions 'events' for jsonpath '{self.events_jsonpath}'.")
            return input_data

        for events_data in events:
            self._normalise_events(events_data.value)

        return input_data


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

        if is_aws_cloud():
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


@pytest.fixture
def sqs_send_task_failure_state_machine(aws_client, create_state_machine, create_iam_role_for_sfn):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_iam_role_for_sfn()
        sm_name: str = f"sqs_send_task_failure_state_machine_{short_uid()}"
        template = CallbackTemplates.load_sfn_template(CallbackTemplates.SQS_FAILURE_ON_TASK_TOKEN)
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


@pytest.fixture
def sqs_send_heartbeat_and_task_success_state_machine(
    aws_client, create_state_machine, create_iam_role_for_sfn
):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_iam_role_for_sfn()
        sm_name: str = f"sqs_send_heartbeat_and_task_success_state_machine_{short_uid()}"
        template = CallbackTemplates.load_sfn_template(
            CallbackTemplates.SQS_HEARTBEAT_SUCCESS_ON_TASK_TOKEN
        )
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


@pytest.fixture
def sfn_events_to_sqs_queue(events_to_sqs_queue, aws_client):
    def _create(state_machine_arn: str) -> str:
        event_pattern = {
            "source": ["aws.states"],
            "detail": {
                "stateMachineArn": [state_machine_arn],
            },
        }
        return events_to_sqs_queue(event_pattern=event_pattern)

    return _create


@pytest.fixture
def events_to_sqs_queue(events_create_rule, sqs_create_queue, sqs_get_queue_arn, aws_client):
    def _setup(event_pattern):
        queue_name = f"test-queue-{short_uid()}"
        rule_name = f"test-rule-{short_uid()}"
        target_id = f"test-target-{short_uid()}"

        rule_arn = events_create_rule(
            Name=rule_name, EventBusName="default", EventPattern=event_pattern
        )

        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_get_queue_arn(queue_url)
        queue_policy = {
            "Statement": [
                {
                    "Sid": "StepFunctionsEventRule",
                    "Resource": queue_arn,
                    "Action": "sqs:SendMessage",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                    "Effect": "Allow",
                }
            ]
        }
        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"Policy": json.dumps(queue_policy), "ReceiveMessageWaitTimeSeconds": "1"},
        )

        aws_client.events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

        return queue_url

    return _setup
