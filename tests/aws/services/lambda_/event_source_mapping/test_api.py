import time

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


class TestLambdaEventSourceMappings:
    @markers.aws.unknown
    @pytest.mark.parametrize(
        "event_source_arn_fixture",
        ["kinesis_stream_arn", "dynamodb_stream_arn", "sqs_standard_queue_arn"],
        ids=["kinesis", "dynamodb", "sqs"],
    )
    def test_create_starting_position_validation_exceptions(
        self,
        snapshot,
        aws_client,
        request,
        event_source_arn_fixture,
        lambda_function_name,
    ):
        unix_epoch = int(time.time())

        # Dynamically create & retrieve the event source ARN
        event_source_arn = request.getfixturevalue(event_source_arn_fixture)

        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_event_source_mapping(
                FunctionName=lambda_function_name,
                EventSourceArn=event_source_arn,
                StartingPosition="0",
            )
        snapshot.match("create_invalid_starting_position_param", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.create_event_source_mapping(
                FunctionName=lambda_function_name,
                EventSourceArn=event_source_arn,
                StartingPosition="LATEST",
                StartingPositionTimestamp=unix_epoch,
            )
        snapshot.match("create_invalid_timestamp_with_starting_position_param", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.create_event_source_mapping(
                FunctionName=lambda_function_name,
                EventSourceArn=event_source_arn,
                StartingPosition="AT_TIMESTAMP",
                StartingPositionTimestamp=-unix_epoch,
            )
        snapshot.match("create_negative_starting_position_timestamp_param", e.value.response)
