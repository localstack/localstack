import json
import os


def handler(event, context):
    # Just print the event that was passed to the Lambda
    print(
        json.dumps(
            {
                "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION"),
                "CUSTOM_VAR": os.environ.get("CUSTOM_VAR"),
                "event": event,
            }
        )
    )
    return event
