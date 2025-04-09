import json
import logging
import os
import shutil
import tempfile
from typing import Final

import pytest
from botocore.config import Config
from localstack_snapshot.snapshots.transformer import (
    JsonpathTransformer,
    RegexTransformer,
)

from localstack.aws.api.stepfunctions import StateMachineType
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest.stepfunctions.utils import await_execution_success
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@pytest.fixture
def sfn_snapshot(snapshot):
    snapshot.add_transformers_list(snapshot.transform.stepfunctions_api())
    return snapshot


@pytest.fixture
def sfn_batch_snapshot(sfn_snapshot):
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..JobDefinition", replacement="job-definition")
    )
    sfn_snapshot.add_transformer(JsonpathTransformer(jsonpath="$..JobName", replacement="job-name"))
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..JobQueue", replacement="job-queue")
    )
    sfn_snapshot.add_transformer(JsonpathTransformer(jsonpath="$..roleArn", replacement="role-arn"))
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..x-amz-apigw-id", replacement="x-amz-apigw-id", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..X-Amzn-Trace-Id", replacement="X-Amzn-Trace-Id", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(JsonpathTransformer(jsonpath="$..TaskArn", replacement="task-arn"))
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..ExecutionRoleArn", replacement="execution-role-arn")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..LogStreamName", replacement="log-stream-name")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..StartedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..StoppedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..CreatedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..PrivateIpv4Address",
            replacement="private-ipv4-address",
            replace_reference=False,
        )
    )
    return sfn_snapshot


@pytest.fixture
def sfn_ecs_snapshot(sfn_snapshot):
    sfn_snapshot.add_transformer(JsonpathTransformer(jsonpath="$..TaskArn", replacement="task_arn"))
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..ContainerArn", replacement="container_arn")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..PrivateIpv4Address", replacement="private_ipv4_address")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..RuntimeId", replacement="runtime_id")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..ImageDigest", replacement="image_digest")
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..PullStartedAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..PullStoppedAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..StartedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..StoppedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..StoppingAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(jsonpath="$..CreatedAt", replacement="time", replace_reference=False)
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..ExecutionStoppedAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..ConnectivityAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..PullStartedAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..PullStoppedAt", replacement="time", replace_reference=False
        )
    )
    sfn_snapshot.add_transformer(RegexTransformer("subnet-[0-9a-zA-Z]+", "subnet_value"))
    sfn_snapshot.add_transformer(RegexTransformer("sg-[0-9a-zA-Z]+", "sg_value"))
    sfn_snapshot.add_transformer(RegexTransformer("eni-[0-9a-zA-Z]+", "eni_value"))
    sfn_snapshot.add_transformer(RegexTransformer("ip-[0-9-]+", "ip_value"))
    sfn_snapshot.add_transformer(
        RegexTransformer(":".join(["[0-9a-z][0-9a-z]?[0-9a-z]?"] * 4), "ip_value")
    )
    sfn_snapshot.add_transformer(RegexTransformer(":".join(["[0-9a-z][0-9a-z]+"] * 6), "mac_value"))
    return sfn_snapshot


@pytest.fixture
def aws_client_no_sync_prefix(aws_client_factory):
    # For StartSyncExecution and TestState calls, boto will prepend "sync-" to the endpoint string.
    # As we operate on localhost, this function creates a new stepfunctions client with that functionality disabled.
    return aws_client_factory(config=Config(inject_host_prefix=is_aws_cloud()))


@pytest.fixture
def mock_config_file():
    tmp_dir = tempfile.mkdtemp()
    file_path = os.path.join(tmp_dir, "MockConfigFile.json")

    def write_json_to_mock_file(mock_config):
        with open(file_path, "w") as df:
            json.dump(mock_config, df)  # noqa
            df.flush()
        return file_path

    try:
        yield write_json_to_mock_file
    finally:
        try:
            os.remove(file_path)
        except Exception as ex:
            LOG.error("Error removing temporary MockConfigFile.json: %s", ex)
        finally:
            shutil.rmtree(
                tmp_dir,
                ignore_errors=True,
                onerror=lambda _, path, exc_info: LOG.error(
                    "Error removing temporary MockConfigFile.json: %s, %s", path, exc_info
                ),
            )


@pytest.fixture
def create_state_machine_iam_role(cleanups, create_state_machine):
    def _create(target_aws_client):
        iam_client = target_aws_client.iam
        stepfunctions_client = target_aws_client.stepfunctions

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
                target_aws_client, name=sm_name, definition=json.dumps(sm_def), roleArn=role_arn
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
def create_state_machine():
    created_state_machine_references = list()

    def _create_state_machine(target_aws_client, **kwargs):
        sfn_client = target_aws_client.stepfunctions
        create_output = sfn_client.create_state_machine(**kwargs)
        create_output_arn = create_output["stateMachineArn"]
        created_state_machine_references.append(
            (create_output_arn, kwargs.get("type", StateMachineType.STANDARD), sfn_client)
        )
        return create_output

    yield _create_state_machine

    # Delete all state machine, attempting to stop all running executions of STANDARD state machines,
    # as other types, such as EXPRESS, cannot be manually stopped.
    for arn, typ, client in created_state_machine_references:
        try:
            if typ == StateMachineType.STANDARD:
                executions = client.list_executions(stateMachineArn=arn)
                for execution in executions["executions"]:
                    client.stop_execution(executionArn=execution["executionArn"])
            client.delete_state_machine(stateMachineArn=arn)
        except Exception as ex:
            LOG.debug("Unable to delete state machine '%s' during cleanup: %s", arn, ex)


@pytest.fixture
def create_state_machine_alias():
    state_machine_alias_arn_and_client = list()

    def _create_state_machine_alias(target_aws_client, **kwargs):
        step_functions_client = target_aws_client.stepfunctions
        create_state_machine_response = step_functions_client.create_state_machine_alias(**kwargs)
        state_machine_alias_arn_and_client.append(
            (create_state_machine_response["stateMachineAliasArn"], step_functions_client)
        )
        return create_state_machine_response

    yield _create_state_machine_alias

    for state_machine_alias_arn, sfn_client in state_machine_alias_arn_and_client:
        try:
            sfn_client.delete_state_machine_alias(stateMachineAliasArn=state_machine_alias_arn)
        except Exception as ex:
            LOG.debug(
                "Unable to delete the state machine alias '%s' during cleanup due '%s'",
                state_machine_alias_arn,
                ex,
            )


@pytest.fixture
def create_activity(aws_client):
    activities_arns: Final[list[str]] = list()

    def _create_activity(**kwargs):
        create_output = aws_client.stepfunctions.create_activity(**kwargs)
        create_output_arn = create_output["activityArn"]
        activities_arns.append(create_output_arn)
        return create_output

    yield _create_activity

    for activity_arn in activities_arns:
        try:
            aws_client.stepfunctions.delete_activity(activityArn=activity_arn)
        except Exception:
            LOG.debug("Unable to delete Activity '%s' during cleanup.", activity_arn)


@pytest.fixture
def sqs_send_task_success_state_machine(
    aws_client, create_state_machine, create_state_machine_iam_role
):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_state_machine_iam_role(aws_client)
        sm_name: str = f"sqs_send_task_success_state_machine_{short_uid()}"

        template = {
            "Comment": "sqs_success_on_task_token",
            "StartAt": "Iterate",
            "States": {
                "Iterate": {
                    "Type": "Pass",
                    "Parameters": {"Count.$": "States.MathAdd($.Iterator.Count, -1)"},
                    "ResultPath": "$.Iterator",
                    "Next": "IterateStep",
                },
                "IterateStep": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.Iterator.Count",
                            "NumericLessThanEquals": 0,
                            "Next": "NoMoreCycles",
                        }
                    ],
                    "Default": "WaitAndReceive",
                },
                "WaitAndReceive": {"Type": "Wait", "Seconds": 1, "Next": "Receive"},
                "Receive": {
                    "Type": "Task",
                    "Parameters": {"QueueUrl.$": "$.QueueUrl"},
                    "Resource": "arn:aws:states:::aws-sdk:sqs:receiveMessage",
                    "ResultPath": "$.SQSOutput",
                    "Next": "CheckMessages",
                },
                "CheckMessages": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.SQSOutput.Messages",
                            "IsPresent": True,
                            "Next": "SendSuccesses",
                        }
                    ],
                    "Default": "Iterate",
                },
                "SendSuccesses": {
                    "Type": "Map",
                    "InputPath": "$.SQSOutput.Messages",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "ParseBody",
                        "States": {
                            "ParseBody": {
                                "Type": "Pass",
                                "Parameters": {"Body.$": "States.StringToJson($.Body)"},
                                "Next": "Send",
                            },
                            "Send": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::aws-sdk:sfn:sendTaskSuccess",
                                "Parameters": {
                                    "Output.$": "States.JsonToString($.Body.Message)",
                                    "TaskToken.$": "$.Body.TaskToken",
                                },
                                "End": True,
                            },
                        },
                    },
                    "ResultPath": None,
                    "Next": "Iterate",
                },
                "NoMoreCycles": {"Type": "Pass", "End": True},
            },
        }

        creation_resp = create_state_machine(
            aws_client, name=sm_name, definition=json.dumps(template), roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({"QueueUrl": sqs_queue_url, "Iterator": {"Count": 300}}),
        )

    return _create_state_machine


@pytest.fixture
def sqs_send_task_failure_state_machine(
    aws_client, create_state_machine, create_state_machine_iam_role
):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_state_machine_iam_role(aws_client)
        sm_name: str = f"sqs_send_task_failure_state_machine_{short_uid()}"

        template = {
            "Comment": "sqs_failure_on_task_token",
            "StartAt": "Iterate",
            "States": {
                "Iterate": {
                    "Type": "Pass",
                    "Parameters": {"Count.$": "States.MathAdd($.Iterator.Count, -1)"},
                    "ResultPath": "$.Iterator",
                    "Next": "IterateStep",
                },
                "IterateStep": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.Iterator.Count",
                            "NumericLessThanEquals": 0,
                            "Next": "NoMoreCycles",
                        }
                    ],
                    "Default": "WaitAndReceive",
                },
                "WaitAndReceive": {"Type": "Wait", "Seconds": 1, "Next": "Receive"},
                "Receive": {
                    "Type": "Task",
                    "Parameters": {"QueueUrl.$": "$.QueueUrl"},
                    "Resource": "arn:aws:states:::aws-sdk:sqs:receiveMessage",
                    "ResultPath": "$.SQSOutput",
                    "Next": "CheckMessages",
                },
                "CheckMessages": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.SQSOutput.Messages",
                            "IsPresent": True,
                            "Next": "SendFailure",
                        }
                    ],
                    "Default": "Iterate",
                },
                "SendFailure": {
                    "Type": "Map",
                    "InputPath": "$.SQSOutput.Messages",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "ParseBody",
                        "States": {
                            "ParseBody": {
                                "Type": "Pass",
                                "Parameters": {"Body.$": "States.StringToJson($.Body)"},
                                "Next": "Send",
                            },
                            "Send": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::aws-sdk:sfn:sendTaskFailure",
                                "Parameters": {
                                    "Error": "Failure error",
                                    "Cause": "Failure cause",
                                    "TaskToken.$": "$.Body.TaskToken",
                                },
                                "End": True,
                            },
                        },
                    },
                    "ResultPath": None,
                    "Next": "Iterate",
                },
                "NoMoreCycles": {"Type": "Pass", "End": True},
            },
        }

        creation_resp = create_state_machine(
            aws_client, name=sm_name, definition=json.dumps(template), roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({"QueueUrl": sqs_queue_url, "Iterator": {"Count": 300}}),
        )

    return _create_state_machine


@pytest.fixture
def sqs_send_heartbeat_and_task_success_state_machine(
    aws_client, create_state_machine, create_state_machine_iam_role
):
    def _create_state_machine(sqs_queue_url):
        snf_role_arn = create_state_machine_iam_role(aws_client)
        sm_name: str = f"sqs_send_heartbeat_and_task_success_state_machine_{short_uid()}"

        template = {
            "Comment": "SQS_HEARTBEAT_SUCCESS_ON_TASK_TOKEN",
            "StartAt": "Iterate",
            "States": {
                "Iterate": {
                    "Type": "Pass",
                    "Parameters": {"Count.$": "States.MathAdd($.Iterator.Count, -1)"},
                    "ResultPath": "$.Iterator",
                    "Next": "IterateStep",
                },
                "IterateStep": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.Iterator.Count",
                            "NumericLessThanEquals": 0,
                            "Next": "NoMoreCycles",
                        }
                    ],
                    "Default": "WaitAndReceive",
                },
                "WaitAndReceive": {"Type": "Wait", "Seconds": 1, "Next": "Receive"},
                "Receive": {
                    "Type": "Task",
                    "Parameters": {"QueueUrl.$": "$.QueueUrl"},
                    "Resource": "arn:aws:states:::aws-sdk:sqs:receiveMessage",
                    "ResultPath": "$.SQSOutput",
                    "Next": "CheckMessages",
                },
                "CheckMessages": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.SQSOutput.Messages",
                            "IsPresent": True,
                            "Next": "SendSuccesses",
                        }
                    ],
                    "Default": "Iterate",
                },
                "SendSuccesses": {
                    "Type": "Map",
                    "InputPath": "$.SQSOutput.Messages",
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "INLINE"},
                        "StartAt": "ParseBody",
                        "States": {
                            "ParseBody": {
                                "Type": "Pass",
                                "Parameters": {"Body.$": "States.StringToJson($.Body)"},
                                "Next": "WaitBeforeHeartbeat",
                            },
                            "WaitBeforeHeartbeat": {
                                "Type": "Wait",
                                "Seconds": 5,
                                "Next": "SendHeartbeat",
                            },
                            "SendHeartbeat": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::aws-sdk:sfn:sendTaskHeartbeat",
                                "Parameters": {"TaskToken.$": "$.Body.TaskToken"},
                                "ResultPath": None,
                                "Next": "SendSuccess",
                            },
                            "SendSuccess": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::aws-sdk:sfn:sendTaskSuccess",
                                "Parameters": {
                                    "Output.$": "States.JsonToString($.Body.Message)",
                                    "TaskToken.$": "$.Body.TaskToken",
                                },
                                "End": True,
                            },
                        },
                    },
                    "ResultPath": None,
                    "Next": "Iterate",
                },
                "NoMoreCycles": {"Type": "Pass", "End": True},
            },
        }

        creation_resp = create_state_machine(
            aws_client, name=sm_name, definition=json.dumps(template), roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({"QueueUrl": sqs_queue_url, "Iterator": {"Count": 300}}),
        )

    return _create_state_machine


@pytest.fixture
def sfn_activity_consumer(aws_client, create_state_machine, create_state_machine_iam_role):
    def _create_state_machine(template, activity_arn):
        snf_role_arn = create_state_machine_iam_role(aws_client)
        sm_name: str = f"activity_send_task_failure_on_task_{short_uid()}"
        definition = json.dumps(template)

        creation_resp = create_state_machine(
            aws_client, name=sm_name, definition=definition, roleArn=snf_role_arn
        )
        state_machine_arn = creation_resp["stateMachineArn"]

        aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn,
            input=json.dumps({"ActivityArn": activity_arn}),
        )

    return _create_state_machine


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


@pytest.fixture
def sfn_events_to_sqs_queue(events_to_sqs_queue):
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
def sfn_glue_create_job(aws_client, create_role, create_policy, wait_and_assume_role):
    job_names = []

    def _execute(**kwargs):
        job_name = f"glue-job-{short_uid()}"

        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Resource": "*",
                },
            ],
        }

        role = create_role(AssumeRolePolicyDocument=json.dumps(assume_role_policy_document))
        role_name = role["Role"]["RoleName"]
        role_arn = role["Role"]["Arn"]

        policy = create_policy(PolicyDocument=json.dumps(policy_document))
        policy_arn = policy["Policy"]["Arn"]

        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn,
        )

        wait_and_assume_role(role_arn)

        aws_client.glue.create_job(Name=job_name, Role=role_arn, **kwargs)

        job_names.append(job_name)
        return job_name

    yield _execute

    for job_name in job_names:
        try:
            aws_client.glue.delete_job(JobName=job_name)
        except Exception as ex:
            # TODO: the glue provider should not fail on deletion of deleted job, however this is currently the case.
            LOG.warning("Could not delete job '%s': %s", job_name, ex)


@pytest.fixture
def sfn_create_log_group(aws_client, snapshot):
    log_group_names = []

    def _create() -> str:
        log_group_name = f"/aws/vendedlogs/states/sfn-test-group-{short_uid()}"
        snapshot.add_transformer(RegexTransformer(log_group_name, "log_group_name"))
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        log_group_names.append(log_group_name)

        return log_group_name

    yield _create

    for log_group_name in log_group_names:
        try:
            aws_client.logs.delete_log_group(logGroupName=log_group_name)
        except Exception:
            LOG.debug("Cannot delete log group %s", log_group_name)


@pytest.fixture
def create_cross_account_admin_role_and_policy(create_state_machine, create_state_machine_iam_role):
    created = list()

    def _create_role_and_policy(trusting_aws_client, trusted_aws_client, trusted_account_id) -> str:
        trusting_iam_client = trusting_aws_client.iam

        role_name = f"admin-test-role-cross-account-{short_uid()}"
        policy_name = f"admin-test-policy-cross-account-{short_uid()}"

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{trusted_account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        create_role_response = trusting_iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )
        role_arn = create_role_response["Role"]["Arn"]

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }

        trusting_iam_client.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
        )

        def _wait_sfn_can_assume_admin_role():
            trusted_stepfunctions_client = trusted_aws_client.stepfunctions
            sm_name = f"test-wait-sfn-can-assume-cross-account-admin-role-{short_uid()}"
            sm_role = create_state_machine_iam_role(trusted_aws_client)
            sm_def = {
                "StartAt": "PullAssumeRole",
                "States": {
                    "PullAssumeRole": {
                        "Type": "Task",
                        "Parameters": {},
                        "Resource": "arn:aws:states:::aws-sdk:s3:listBuckets",
                        "Credentials": {"RoleArn": role_arn},
                        "Retry": [
                            {
                                "ErrorEquals": ["States.ALL"],
                                "IntervalSeconds": 2,
                                "MaxAttempts": 60,
                            }
                        ],
                        "End": True,
                    }
                },
            }
            creation_response = create_state_machine(
                trusted_aws_client, name=sm_name, definition=json.dumps(sm_def), roleArn=sm_role
            )
            state_machine_arn = creation_response["stateMachineArn"]

            exec_resp = trusted_stepfunctions_client.start_execution(
                stateMachineArn=state_machine_arn, input="{}"
            )
            execution_arn = exec_resp["executionArn"]

            await_execution_success(
                stepfunctions_client=trusted_stepfunctions_client, execution_arn=execution_arn
            )

            trusted_stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)

        if is_aws_cloud():
            _wait_sfn_can_assume_admin_role()

        return role_arn

    yield _create_role_and_policy

    for aws_client, role_name, policy_name in created:
        aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        aws_client.iam.delete_role(RoleName=role_name)
