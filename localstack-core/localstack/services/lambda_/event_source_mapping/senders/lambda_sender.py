import json
import logging

from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.api.pipes import PipeTargetInvocationType
from localstack.services.lambda_.api_utils import function_locators_from_arn
from localstack.services.lambda_.event_source_mapping.pipe_utils import to_json_str
from localstack.services.lambda_.event_source_mapping.pollers.poller import has_batch_item_failures
from localstack.services.lambda_.event_source_mapping.senders.sender import (
    PartialFailureSenderError,
    Sender,
    SenderError,
)

LOG = logging.getLogger(__name__)


class LambdaSender(Sender):
    # Flag to enable the payload dict using the "Records" key used for Lambda event source mapping
    payload_dict: bool

    # Flag to enable partial successes/failures when processing batched events through a Lambda event source mapping
    report_batch_item_failures: bool

    def __init__(
        self,
        target_arn,
        target_parameters=None,
        target_client=None,
        payload_dict=False,
        report_batch_item_failures=False,
    ):
        super().__init__(target_arn, target_parameters, target_client)
        self.payload_dict = payload_dict
        self.report_batch_item_failures = report_batch_item_failures

    def send_events(self, events: list[dict] | dict) -> dict:
        if self.payload_dict:
            events = {"Records": events}
        # TODO: test qualified + unqualified Lambda invoke
        # According to Pipe trace logs, the internal awsRequest contains a qualifier, even if "null"
        _, qualifier, _, _ = function_locators_from_arn(self.target_arn)
        optional_qualifier = {}
        if qualifier is not None:
            optional_qualifier["Qualifier"] = qualifier
        invocation_type = InvocationType.RequestResponse
        if (
            self.target_parameters.get("LambdaFunctionParameters", {}).get("InvocationType")
            == PipeTargetInvocationType.FIRE_AND_FORGET
        ):
            invocation_type = InvocationType.Event

        # TODO: test special payloads (e.g., None, str, empty str, bytes)
        #  see "to_bytes(json.dumps(payload or {}, cls=BytesEncoder))" in legacy invoke adapter
        #  localstack.services.lambda_.event_source_listeners.adapters.EventSourceAsfAdapter.invoke_with_statuscode
        invoke_result = self.target_client.invoke(
            FunctionName=self.target_arn,
            Payload=to_json_str(events),
            InvocationType=invocation_type,
            **optional_qualifier,
        )

        try:
            payload = json.load(invoke_result["Payload"])
        except json.JSONDecodeError:
            payload = None
            LOG.debug(
                "Payload from Lambda invocation '%s' is invalid json. Setting this to 'None'",
                invoke_result["Payload"],
            )

        if function_error := invoke_result.get("FunctionError"):
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
                "exceptionType": "BadRequest",  # Currently only used in Pipes
                "resourceArn": self.target_arn,
                "functionError": function_error,
                "executedVersion": invoke_result.get("ExecutedVersion", "$LATEST"),
            }
            raise SenderError(
                f"Error during sending events {events} due to FunctionError {function_error}.",
                error=error,
            )

        # The payload can contain the key "batchItemFailures" with a list of partial batch failures:
        # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html
        if self.report_batch_item_failures and has_batch_item_failures(payload):
            error = {
                "message": "Target invocation failed partially.",
                "httpStatusCode": invoke_result["StatusCode"],
                "awsService": "lambda",
                "requestId": invoke_result["ResponseMetadata"]["RequestId"],
                "exceptionType": "BadRequest",
                "resourceArn": self.target_arn,
                "executedVersion": invoke_result.get("ExecutedVersion", "$LATEST"),
            }
            raise PartialFailureSenderError(error=error, partial_failure_payload=payload)

        return payload
