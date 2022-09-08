import json
import time

import pytest

from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition, retry
from tests.integration.awslambda.test_lambda import (
    PYTHON_TEST_RUNTIMES,
    TEST_LAMBDA_PUT_ITEM_FILE,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_SEND_MESSAGE_FILE,
    TEST_LAMBDA_START_EXECUTION_FILE,
)

parametrize_python_runtimes = pytest.mark.parametrize("runtime", PYTHON_TEST_RUNTIMES)


class TestLambdaOutgoingSdkCalls:
    @parametrize_python_runtimes
    # from lambda integration test - what to do?
    def test_lambda_send_message_to_sqs(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        runtime,
        lambda_su_role,
    ):
        """Send sqs message to sqs queue inside python lambda"""
        function_name = f"test-function-{short_uid()}"
        queue_name = f"lambda-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        create_lambda_function(
            handler_file=TEST_LAMBDA_SEND_MESSAGE_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        event = {
            "message": f"message-from-test-lambda-{short_uid()}",
            "queue_name": queue_name,
            "region_name": sqs_client.meta.region_name,
        }

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        # assert that message has been received on the Queue
        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            return rs["Messages"][0]

        message = retry(receive_message, retries=15, sleep=2)
        assert event["message"] == message["Body"]

    @parametrize_python_runtimes
    # from lambda integration test
    def test_lambda_put_item_to_dynamodb(
        self,
        lambda_client,
        create_lambda_function,
        dynamodb_create_table,
        runtime,
        dynamodb_resource,
        lambda_su_role,
        dynamodb_client,
    ):
        """Put item into dynamodb from python lambda"""
        table_name = f"ddb-table-{short_uid()}"
        function_name = f"test-function-{short_uid()}"

        dynamodb_create_table(table_name=table_name, partition_key="id")

        create_lambda_function(
            handler_file=TEST_LAMBDA_PUT_ITEM_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        data = {short_uid(): f"data-{i}" for i in range(3)}

        event = {
            "table_name": table_name,
            "region_name": dynamodb_client.meta.region_name,
            "items": [{"id": k, "data": v} for k, v in data.items()],
        }

        def wait_for_table_created():
            return (
                dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"]
                == "ACTIVE"
            )

        assert poll_condition(wait_for_table_created, timeout=30)

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        rs = dynamodb_resource.Table(table_name).scan()

        items = rs["Items"]

        assert len(items) == len(data.keys())
        for item in items:
            assert data[item["id"]] == item["data"]

    @parametrize_python_runtimes
    # from lambda integration test
    def test_lambda_start_stepfunctions_execution(
        self, lambda_client, stepfunctions_client, create_lambda_function, runtime, lambda_su_role
    ):
        """Start stepfunctions machine execution from lambda"""
        function_name = f"test-function-{short_uid()}"
        resource_lambda_name = f"test-resource-{short_uid()}"
        state_machine_name = f"state-machine-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_START_EXECUTION_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        resource_lambda_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=resource_lambda_name,
            runtime=runtime,
            role=lambda_su_role,
        )["CreateFunctionResponse"]["FunctionArn"]

        state_machine_def = {
            "StartAt": "step1",
            "States": {
                "step1": {
                    "Type": "Task",
                    "Resource": resource_lambda_arn,
                    "ResultPath": "$.result_value",
                    "End": True,
                }
            },
        }

        rs = stepfunctions_client.create_state_machine(
            name=state_machine_name,
            definition=json.dumps(state_machine_def),
            roleArn=lambda_su_role,
        )
        sm_arn = rs["stateMachineArn"]

        try:
            lambda_client.invoke(
                FunctionName=function_name,
                Payload=json.dumps(
                    {
                        "state_machine_arn": sm_arn,
                        "region_name": stepfunctions_client.meta.region_name,
                        "input": {},
                    }
                ),
            )
            time.sleep(1)

            rs = stepfunctions_client.list_executions(stateMachineArn=sm_arn)

            # assert that state machine get executed 1 time
            assert 1 == len([ex for ex in rs["executions"] if ex["stateMachineArn"] == sm_arn])

        finally:
            # clean up
            stepfunctions_client.delete_state_machine(stateMachineArn=sm_arn)
