import json
import logging

from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.api.pipes import PipeTargetInvocationType
from localstack.services.lambda_.event_source_mapping.pollers.poller import has_batch_item_failures
from localstack.services.lambda_.event_source_mapping.senders.sender import (
    PartialFailureSenderError,
    Sender,
    SenderError,
)
from localstack.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)


class LambdaSender(Sender):
    # Flag to enable the payload dict using the "Records" key used for Lambda event source mapping
    payload_dict: bool

    def __init__(self, target_arn, target_parameters=None, target_client=None, payload_dict=False):
        super().__init__(target_arn, target_parameters, target_client)
        self.payload_dict = payload_dict

    def send_events(self, events: list[dict]) -> dict:
        if self.payload_dict:
            events = {"Records": events}
        parsed_arn = parse_arn(self.target_arn)
        # TODO: test qualified Lambda invoke
        optional_qualifier = {}
        if qualifier := parsed_arn.get("qualifier"):
            optional_qualifier["Qualifier"] = qualifier
        invocation_type = InvocationType.RequestResponse
        if (
            self.target_parameters.get("LambdaFunctionParameters", {}).get("InvocationType")
            == PipeTargetInvocationType.FIRE_AND_FORGET
        ):
            invocation_type = InvocationType.Event

        invoke_result = self.target_client.invoke(
            FunctionName=self.target_arn,
            Payload=json.dumps(events),
            InvocationType=invocation_type,
            **optional_qualifier,
        )
        payload = json.load(invoke_result["Payload"])
        if "FunctionError" in invoke_result:
            function_error = invoke_result["FunctionError"]
            LOG.debug(
                "Pipe target function %s failed with FunctionError %s. Payload: %s",
                self.target_arn,
                function_error,
                payload,
            )
            error = {
                "message": f"Target {self.target_arn} encountered an error while processing event(s).",
                "httpStatusCode": invoke_result["StatusCode"],
                "awsService": "lambda",
                "requestId": invoke_result["ResponseMetadata"]["RequestId"],
                # TODO: fix hardcoded value by figuring out what other exception types exist
                "exceptionType": "BadRequest",
                "resourceArn": self.target_arn,
            }
            raise SenderError(
                f"Error during sending events {events} due to FunctionError {function_error}.",
                error=error,
            )

        # TODO: test all success, partial, and failure conditions:
        #   https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-dynamodb.html#pipes-ddb-batch-failures
        # The payload can contain the key "batchItemFailures" with a list of partial batch failures:
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
        if has_batch_item_failures(payload):
            error = {
                "message": "Target invocation failed partially.",
                "httpStatusCode": invoke_result["StatusCode"],
                "awsService": "lambda",
                "requestId": invoke_result["ResponseMetadata"]["RequestId"],
                "exceptionType": "BadRequest",
                "resourceArn": self.target_arn,
            }
            raise PartialFailureSenderError(error=error, partial_failure_payload=payload)

        return payload
