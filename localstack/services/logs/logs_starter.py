import base64
import io
import json
from gzip import GzipFile

from moto.awslambda import models as lambda_models
from moto.core.utils import unix_time_millis
from moto.logs import models as logs_models
from moto.logs.exceptions import InvalidParameterException, ResourceNotFoundException
from moto.logs.models import LogStream

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.aws import aws_stack


def patch_logs():
    def patch_get_function(backend):
        get_function_orig = backend.get_function

        def get_function(*args, **kwargs):
            result = get_function_orig(*args, **kwargs)
            if result:
                return result
            # in case if lambda is not present in moto fall back to
            #  fetching Lambda details from LocalStack API directly
            client = aws_stack.connect_to_service("lambda")
            lambda_name = aws_stack.lambda_function_name(args[0])
            response = client.get_function(FunctionName=lambda_name)
            return response

        return get_function

    def patch_put_subscription_filter(backend):
        def put_subscription_filter(*args, **kwargs):
            log_group_name = args[0]
            filter_name = args[1]
            filter_pattern = args[2]
            destination_arn = args[3]
            role_arn = args[4]

            log_group = logs_models.logs_backends[aws_stack.get_region()].groups.get(log_group_name)

            if not log_group:
                raise ResourceNotFoundException("The specified log group does not exist.")

            if ":lambda:" in destination_arn:
                client = aws_stack.connect_to_service("lambda")
                lambda_name = aws_stack.lambda_function_name(destination_arn)
                try:
                    client.get_function(FunctionName=lambda_name)
                except Exception:
                    raise InvalidParameterException(
                        "destinationArn for vendor lambda cannot be used with roleArn"
                    )

            elif ":kinesis:" in destination_arn:
                client = aws_stack.connect_to_service("kinesis")
                stream_name = aws_stack.kinesis_stream_name(destination_arn)
                try:
                    client.describe_stream(StreamName=stream_name)
                except Exception:
                    raise InvalidParameterException(
                        "Could not deliver test message to specified Kinesis stream. "
                        "Check if the given kinesis stream is in ACTIVE state. "
                    )

            elif ":firehose:" in destination_arn:
                client = aws_stack.connect_to_service("firehose")
                firehose_name = aws_stack.firehose_name(destination_arn)
                try:
                    client.describe_delivery_stream(DeliveryStreamName=firehose_name)
                except Exception:
                    raise InvalidParameterException(
                        "Could not deliver test message to specified Firehose stream. "
                        "Check if the given Firehose stream is in ACTIVE state."
                    )

            else:
                service = aws_stack.extract_service_from_arn(destination_arn)
                raise InvalidParameterException(
                    "PutSubscriptionFilter operation cannot work with destinationArn for vendor %s"
                    % service
                )

            log_group.put_subscription_filter(
                filter_name, filter_pattern, destination_arn, role_arn
            )

        return put_subscription_filter

    def put_log_events_model(self, log_group_name, log_stream_name, log_events, sequence_token):
        # TODO: call/patch upstream method here, instead of duplicating the code!
        self.last_ingestion_time = int(unix_time_millis())
        self.stored_bytes += sum([len(log_event["message"]) for log_event in log_events])
        events = [
            logs_models.LogEvent(self.last_ingestion_time, log_event) for log_event in log_events
        ]
        self.events += events
        self.upload_sequence_token += 1

        log_events = [
            {
                "id": event.event_id,
                "timestamp": event.timestamp,
                "message": event.message,
            }
            for event in events
        ]

        data = {
            "messageType": "DATA_MESSAGE",
            "owner": aws_stack.get_account_id(),
            "logGroup": log_group_name,
            "logStream": log_stream_name,
            "subscriptionFilters": [self.filter_name],
            "logEvents": log_events,
        }

        output = io.BytesIO()
        with GzipFile(fileobj=output, mode="w") as f:
            f.write(json.dumps(data, separators=(",", ":")).encode("utf-8"))
        payload_gz_encoded = base64.b64encode(output.getvalue()).decode("utf-8")
        event = {"awslogs": {"data": payload_gz_encoded}}

        if self.destination_arn:
            if ":lambda:" in self.destination_arn:
                client = aws_stack.connect_to_service("lambda")
                lambda_name = aws_stack.lambda_function_name(self.destination_arn)
                client.invoke(FunctionName=lambda_name, Payload=json.dumps(event))
            if ":kinesis:" in self.destination_arn:
                client = aws_stack.connect_to_service("kinesis")
                stream_name = aws_stack.kinesis_stream_name(self.destination_arn)
                client.put_record(
                    StreamName=stream_name,
                    Data=json.dumps(payload_gz_encoded),
                    PartitionKey=log_group_name,
                )
            if ":firehose:" in self.destination_arn:
                client = aws_stack.connect_to_service("firehose")
                firehose_name = aws_stack.firehose_name(self.destination_arn)
                client.put_record(
                    DeliveryStreamName=firehose_name,
                    Record={"Data": json.dumps(payload_gz_encoded)},
                )

    setattr(LogStream, "put_log_events", put_log_events_model)

    for lambda_backend in lambda_models.lambda_backends.values():
        lambda_backend.get_function = patch_get_function(lambda_backend)
    for logs_backend in logs_models.logs_backends.values():
        logs_backend.put_subscription_filter = patch_put_subscription_filter(logs_backend)


def start_cloudwatch_logs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_LOGS
    patch_logs()
    return start_moto_server(
        "logs",
        port,
        name="CloudWatch Logs",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
