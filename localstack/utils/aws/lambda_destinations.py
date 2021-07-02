import json

from localstack.utils.aws.aws_stack import send_event_to_target
from localstack.utils.common import long_uid, timestamp_millis


def lambda_result_to_destination(func_details, event, result, is_async, error):
    if not func_details.destination_enabled():
        return

    payload = {
        "version": "1.0",
        "timestamp": timestamp_millis(),
        "requestContext": {
            "requestId": long_uid(),
            "functionArn": func_details.arn(),
            "condition": "RetriesExhausted",
            "approximateInvokeCount": 1,
        },
        "requestPayload": event,
        "responseContext": {"statusCode": 200, "executedVersion": "$LATEST"},
        "responsePayload": {},
    }

    if result and result.result:
        try:
            payload["requestContext"]["condition"] = "Success"
            payload["responsePayload"] = json.loads(result.result)
        except Exception:
            payload["responsePayload"] = result.result

    if error:
        payload["responseContext"]["functionError"] = "Unhandled"
        # add the result in the response payload
        if error.result is not None:
            payload["responsePayload"] = json.loads(error.result)
        send_event_to_target(func_details.on_failed_invocation, payload)
        return

    send_event_to_target(func_details.on_successful_invocation, payload)
