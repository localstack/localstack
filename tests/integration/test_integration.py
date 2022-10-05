# -*- coding: utf-8 -*-

import base64
import json
import logging
import re
import time
from datetime import datetime, timedelta

import pytest

from localstack.testing.aws.util import get_lambda_logs
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    clone,
    load_file,
    new_tmp_file,
    retry,
    save_file,
    short_uid,
    to_bytes,
    to_str,
)
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.sync import poll_condition

from .awslambda.functions import lambda_integration
from .awslambda.test_lambda import (
    PYTHON_TEST_RUNTIMES,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PUT_ITEM_FILE,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_SEND_MESSAGE_FILE,
    TEST_LAMBDA_START_EXECUTION_FILE,
)

TEST_LAMBDA_SOURCE_STREAM_NAME = "test_source_stream"
TEST_BUCKET_NAME = lambda_integration.TEST_BUCKET_NAME
TEST_TOPIC_NAME = "test_topic"
TEST_TAGS = [{"Key": "MyTag", "Value": "Value"}]

PARTITION_KEY = "id"

# set up logger
LOGGER = logging.getLogger(__name__)

TEST_HANDLER = """
def handler(event, *args):
    return {}
"""


@pytest.fixture(scope="class")
def scheduled_test_lambda():
    # Note: create scheduled Lambda here - assertions will be run in test_scheduled_lambda() below..

    # create test Lambda
    scheduled_lambda_name = "scheduled-%s" % short_uid()
    handler_file = new_tmp_file()
    save_file(handler_file, TEST_HANDLER)
    resp = testutil.create_lambda_function(
        handler_file=handler_file, func_name=scheduled_lambda_name
    )
    func_arn = resp["CreateFunctionResponse"]["FunctionArn"]

    # create scheduled Lambda function
    rule_name = "rule-%s" % short_uid()
    events = aws_stack.create_external_boto_client("events")
    events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minutes)")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target-%s" % short_uid(), "Arn": func_arn}])

    yield scheduled_lambda_name

    testutil.delete_lambda_function(scheduled_lambda_name)


@pytest.mark.usefixtures("scheduled_test_lambda")
class TestIntegration:
    def test_firehose_s3(
        self, s3_resource, firehose_client, firehose_create_delivery_stream, s3_create_bucket
    ):
        stream_name = f"fh-stream-{short_uid()}"
        bucket_name = s3_create_bucket()

        s3_prefix = "/testdata"
        test_data = '{"test": "firehose_data_%s"}' % short_uid()
        # create Firehose stream
        stream = firehose_create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "BucketARN": aws_stack.s3_bucket_arn(bucket_name),
                "Prefix": s3_prefix,
            },
            Tags=TEST_TAGS,
        )
        assert stream
        assert stream_name in firehose_client.list_delivery_streams()["DeliveryStreamNames"]
        tags = firehose_client.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
        assert TEST_TAGS == tags["Tags"]
        # create target S3 bucket
        s3_resource.create_bucket(Bucket=bucket_name)

        # put records
        firehose_client.put_record(
            DeliveryStreamName=stream_name, Record={"Data": to_bytes(test_data)}
        )
        # check records in target bucket
        all_objects = testutil.list_all_s3_objects()
        testutil.assert_objects(json.loads(to_str(test_data)), all_objects)
        # check file layout in target bucket
        all_objects = testutil.map_all_s3_objects(buckets=[bucket_name])
        for key in all_objects.keys():
            assert re.match(r".*/\d{4}/\d{2}/\d{2}/\d{2}/.*-\d{4}-\d{2}-\d{2}-\d{2}.*", key)

    def test_firehose_extended_s3(
        self, firehose_client, firehose_create_delivery_stream, s3_create_bucket
    ):
        stream_name = f"fh-stream-{short_uid()}"
        bucket_name = s3_create_bucket()

        s3_prefix = "/testdata2"
        test_data = '{"test": "firehose_data_%s"}' % short_uid()
        # create Firehose stream
        stream = firehose_create_delivery_stream(
            DeliveryStreamName=stream_name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "BucketARN": aws_stack.s3_bucket_arn(bucket_name),
                "Prefix": s3_prefix,
            },
            Tags=TEST_TAGS,
        )

        assert stream
        assert stream_name in firehose_client.list_delivery_streams()["DeliveryStreamNames"]
        tags = firehose_client.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
        assert tags["Tags"] == TEST_TAGS

        # put records
        firehose_client.put_record(
            DeliveryStreamName=stream_name, Record={"Data": to_bytes(test_data)}
        )
        # check records in target bucket
        all_objects = testutil.list_all_s3_objects()
        testutil.assert_objects(json.loads(to_str(test_data)), all_objects)
        # check file layout in target bucket
        all_objects = testutil.map_all_s3_objects(buckets=[bucket_name])
        for key in all_objects.keys():
            assert re.match(r".*/\d{4}/\d{2}/\d{2}/\d{2}/.*-\d{4}-\d{2}-\d{2}-\d{2}.*", key)

    def test_firehose_kinesis_to_s3(
        self, kinesis_client, s3_resource, firehose_client, kinesis_create_stream
    ):
        stream_name = f"fh-stream-{short_uid()}"

        kinesis_stream_name = kinesis_create_stream()

        s3_prefix = "/testdata"
        test_data = '{"test": "firehose_data_%s"}' % short_uid()

        # create Firehose stream
        stream = firehose_client.create_delivery_stream(
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "KinesisStreamARN": aws_stack.kinesis_stream_arn(kinesis_stream_name),
            },
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "BucketARN": aws_stack.s3_bucket_arn(TEST_BUCKET_NAME),
                "Prefix": s3_prefix,
            },
        )
        assert stream
        assert stream_name in firehose_client.list_delivery_streams()["DeliveryStreamNames"]

        # wait for stream to become ACTIVE
        def _assert_active():
            stream_info = firehose_client.describe_delivery_stream(DeliveryStreamName=stream_name)
            assert stream_info["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

        retry(_assert_active, sleep=1, retries=30)

        # create target S3 bucket
        s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME)

        # put records
        kinesis_client.put_record(
            Data=to_bytes(test_data), PartitionKey="testId", StreamName=kinesis_stream_name
        )

        # check records in target bucket
        def _assert_objects_created():
            all_objects = testutil.list_all_s3_objects()
            testutil.assert_objects(json.loads(to_str(test_data)), all_objects)

        retry(_assert_objects_created, sleep=1, retries=4)

        # clean up
        firehose_client.delete_delivery_stream(DeliveryStreamName=stream_name)

    def test_lambda_streams_batch_and_transactions(
        self,
        dynamodb_client,
        dynamodbstreams_client,
        kinesis_create_stream,
        dynamodb_create_table,
        create_lambda_function,
    ):
        ddb_lease_table_suffix = "-kclapp2"
        table_name = short_uid() + "lsbat" + ddb_lease_table_suffix
        lambda_ddb_name = f"lambda-ddb-{short_uid()}"
        stream_name = kinesis_create_stream()

        events = []

        # subscribe to inbound Kinesis stream
        def process_records(records, shard_id):
            events.extend(records)

        # start the KCL client process in the background
        process = kinesis_connector.listen_to_kinesis(
            stream_name,
            listener_func=process_records,
            wait_until_started=True,
            ddb_lease_table_suffix=ddb_lease_table_suffix,
        )

        LOGGER.info("Kinesis consumer initialized.")
        try:
            # create table with stream forwarding config
            dynamodb_create_table(
                table_name=table_name,
                partition_key=PARTITION_KEY,
                stream_view_type="NEW_AND_OLD_IMAGES",
            )

            # list DDB streams and make sure the table stream is there
            streams = dynamodbstreams_client.list_streams()
            ddb_event_source_arn = None
            for stream in streams["Streams"]:
                if stream["TableName"] == table_name:
                    ddb_event_source_arn = stream["StreamArn"]
            assert ddb_event_source_arn

            # deploy test lambda connected to DynamoDB Stream
            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON,
                libs=TEST_LAMBDA_LIBS,
                func_name=lambda_ddb_name,
                event_source_arn=ddb_event_source_arn,
                starting_position="TRIM_HORIZON",
                delete=True,
                envvars={"KINESIS_STREAM_NAME": stream_name},
            )

            # submit a batch with writes
            dynamodb_client.batch_write_item(
                RequestItems={
                    table_name: [
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId0"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId1"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId2"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                    ]
                }
            )

            # submit a batch with writes and deletes
            dynamodb_client.batch_write_item(
                RequestItems={
                    table_name: [
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId3"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId4"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                        {
                            "PutRequest": {
                                "Item": {
                                    PARTITION_KEY: {"S": "testId5"},
                                    "data": {"S": "foobar123"},
                                }
                            }
                        },
                        {"DeleteRequest": {"Key": {PARTITION_KEY: {"S": "testId0"}}}},
                        {"DeleteRequest": {"Key": {PARTITION_KEY: {"S": "testId1"}}}},
                        {"DeleteRequest": {"Key": {PARTITION_KEY: {"S": "testId2"}}}},
                    ]
                }
            )

            # submit a transaction with writes and delete
            dynamodb_client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                PARTITION_KEY: {"S": "testId6"},
                                "data": {"S": "foobar123"},
                            },
                        }
                    },
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                PARTITION_KEY: {"S": "testId7"},
                                "data": {"S": "foobar123"},
                            },
                        }
                    },
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                PARTITION_KEY: {"S": "testId8"},
                                "data": {"S": "foobar123"},
                            },
                        }
                    },
                    {
                        "Delete": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId3"}},
                        }
                    },
                    {
                        "Delete": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId4"}},
                        }
                    },
                    {
                        "Delete": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId5"}},
                        }
                    },
                ]
            )

            # submit a batch with a put over existing item
            dynamodb_client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                PARTITION_KEY: {"S": "testId6"},
                                "data": {"S": "foobar123_updated1"},
                            },
                        }
                    },
                ]
            )

            # submit a transaction with a put over existing item
            dynamodb_client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": table_name,
                            "Item": {
                                PARTITION_KEY: {"S": "testId7"},
                                "data": {"S": "foobar123_updated1"},
                            },
                        }
                    },
                ]
            )

            # submit a transaction with updates
            dynamodb_client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId6"}},
                            "UpdateExpression": "SET #0 = :0",
                            "ExpressionAttributeNames": {"#0": "data"},
                            "ExpressionAttributeValues": {":0": {"S": "foobar123_updated2"}},
                        }
                    },
                    {
                        "Update": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId7"}},
                            "UpdateExpression": "SET #0 = :0",
                            "ExpressionAttributeNames": {"#0": "data"},
                            "ExpressionAttributeValues": {":0": {"S": "foobar123_updated2"}},
                        }
                    },
                    {
                        "Update": {
                            "TableName": table_name,
                            "Key": {PARTITION_KEY: {"S": "testId8"}},
                            "UpdateExpression": "SET #0 = :0",
                            "ExpressionAttributeNames": {"#0": "data"},
                            "ExpressionAttributeValues": {":0": {"S": "foobar123_updated2"}},
                        }
                    },
                ]
            )

            LOGGER.info("Waiting some time before finishing test.")
            time.sleep(2)

            num_insert = 9
            num_modify = 5
            num_delete = 6
            num_events = num_insert + num_modify + num_delete

            def check_events():
                if len(events) != num_events:
                    msg = "DynamoDB updates retrieved (actual/expected): %s/%s" % (
                        len(events),
                        num_events,
                    )
                    LOGGER.warning(msg)
                assert len(events) == num_events
                event_items = [json.loads(base64.b64decode(e["data"])) for e in events]
                # make sure that we have the right amount of expected event types
                inserts = [e for e in event_items if e.get("__action_type") == "INSERT"]
                modifies = [e for e in event_items if e.get("__action_type") == "MODIFY"]
                removes = [e for e in event_items if e.get("__action_type") == "REMOVE"]
                assert len(inserts) == num_insert
                assert len(modifies) == num_modify
                assert len(removes) == num_delete

                # assert that all inserts were received

                for i, event in enumerate(inserts):
                    assert "old_image" not in event
                    item_id = "testId%d" % i
                    matching = [i for i in inserts if i["new_image"]["id"] == item_id][0]
                    assert matching["new_image"] == {"id": item_id, "data": "foobar123"}

                # assert that all updates were received

                def assert_updates(expected_updates, modifies):
                    def found(update):
                        for modif in modifies:
                            if modif["old_image"]["id"] == update["id"]:
                                assert modif["old_image"] == {
                                    "id": update["id"],
                                    "data": update["old"],
                                }
                                assert modif["new_image"] == {
                                    "id": update["id"],
                                    "data": update["new"],
                                }
                                return True

                    for update in expected_updates:
                        assert found(update)

                updates1 = [
                    {"id": "testId6", "old": "foobar123", "new": "foobar123_updated1"},
                    {"id": "testId7", "old": "foobar123", "new": "foobar123_updated1"},
                ]
                updates2 = [
                    {
                        "id": "testId6",
                        "old": "foobar123_updated1",
                        "new": "foobar123_updated2",
                    },
                    {
                        "id": "testId7",
                        "old": "foobar123_updated1",
                        "new": "foobar123_updated2",
                    },
                    {"id": "testId8", "old": "foobar123", "new": "foobar123_updated2"},
                ]

                assert_updates(updates1, modifies[:2])
                assert_updates(updates2, modifies[2:])

                # assert that all removes were received

                for i, event in enumerate(removes):
                    assert "new_image" not in event
                    item_id = "testId%d" % i
                    matching = [i for i in removes if i["old_image"]["id"] == item_id][0]
                    assert matching["old_image"] == {"id": item_id, "data": "foobar123"}

            # this can take a long time in CI, make sure we give it enough time/retries
            retry(check_events, retries=30, sleep=4)

        finally:
            # cleanup
            process.stop()

    def test_scheduled_lambda(self, scheduled_test_lambda):
        def check_invocation(*args):
            log_events = get_lambda_logs(scheduled_test_lambda)
            assert log_events

        # wait for up to 1 min for invocations to get triggered
        retry(check_invocation, retries=14, sleep=5)


def test_kinesis_lambda_forward_chain(
    kinesis_client,
    s3_client,
    lambda_client,
    kinesis_create_stream,
    create_lambda_function,
    cleanups,
):
    stream1_name = kinesis_create_stream()
    stream2_name = kinesis_create_stream()
    lambda1_name = f"function-{short_uid()}"
    lambda2_name = f"function-{short_uid()}"
    s3_client.create_bucket(Bucket=TEST_BUCKET_NAME)

    # deploy test lambdas connected to Kinesis streams
    zip_file = testutil.create_lambda_archive(
        load_file(TEST_LAMBDA_PYTHON), get_content=True, libs=TEST_LAMBDA_LIBS
    )
    lambda_1_resp = create_lambda_function(
        func_name=lambda1_name,
        zip_file=zip_file,
        event_source_arn=get_event_source_arn(stream1_name),
        starting_position="TRIM_HORIZON",
    )
    lambda_1_event_source_uuid = lambda_1_resp["CreateEventSourceMappingResponse"]["UUID"]
    cleanups.append(
        lambda: lambda_client.delete_event_source_mapping(UUID=lambda_1_event_source_uuid)
    )
    lambda_2_resp = create_lambda_function(
        func_name=lambda2_name,
        zip_file=zip_file,
        event_source_arn=get_event_source_arn(stream2_name),
        starting_position="TRIM_HORIZON",
    )
    lambda_2_event_source_uuid = lambda_2_resp["CreateEventSourceMappingResponse"]["UUID"]
    cleanups.append(
        lambda: lambda_client.delete_event_source_mapping(UUID=lambda_2_event_source_uuid)
    )

    # publish test record
    test_data = {"test_data": "forward_chain_data_%s with 'quotes\\\"" % short_uid()}
    data = clone(test_data)
    data[lambda_integration.MSG_BODY_MESSAGE_TARGET] = "kinesis:%s" % stream2_name
    LOGGER.debug("put record")
    kinesis_client.put_record(
        Data=to_bytes(json.dumps(data)),
        PartitionKey="testId",
        StreamName=stream1_name,
    )

    def check_results():
        LOGGER.debug("check results")
        all_objects = testutil.list_all_s3_objects()
        testutil.assert_objects(test_data, all_objects)

    # check results
    retry(check_results, retries=10, sleep=3)


parametrize_python_runtimes = pytest.mark.parametrize("runtime", PYTHON_TEST_RUNTIMES)


class TestLambdaOutgoingSdkCalls:
    @parametrize_python_runtimes
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
    def test_lambda_start_stepfunctions_execution(
        self,
        lambda_client,
        stepfunctions_client,
        create_lambda_function,
        runtime,
        lambda_su_role,
        cleanups,
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
        cleanups.append(lambda: stepfunctions_client.delete_state_machine(stateMachineArn=sm_arn))

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

        # assert that state machine got executed 1 time
        assert 1 == len([ex for ex in rs["executions"] if ex["stateMachineArn"] == sm_arn])


# ---------------
# HELPER METHODS
# ---------------


def get_event_source_arn(stream_name):
    kinesis = aws_stack.create_external_boto_client("kinesis")
    return kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamARN"]


def get_lambda_invocations_count(
    lambda_name, metric=None, period=None, start_time=None, end_time=None
):
    metric = get_lambda_metrics(lambda_name, metric, period, start_time, end_time)
    if not metric["Datapoints"]:
        return 0
    return metric["Datapoints"][-1]["Sum"]


def get_lambda_metrics(func_name, metric=None, period=None, start_time=None, end_time=None):
    metric = metric or "Invocations"
    cloudwatch = aws_stack.create_external_boto_client("cloudwatch")
    period = period or 600
    end_time = end_time or datetime.now()
    if start_time is None:
        start_time = end_time - timedelta(seconds=period)
    return cloudwatch.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric,
        Dimensions=[{"Name": "FunctionName", "Value": func_name}],
        Period=period,
        StartTime=start_time,
        EndTime=end_time,
        Statistics=["Sum"],
    )
