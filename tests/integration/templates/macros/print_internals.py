import json


def handler(event, context):
    fragment = event["fragment"]

    fragment["Resources"]["Parameter"]["Properties"]["Value"] = json.dumps(
        {
            "Event": event,
            # TODO find a way to print context class
            # "Context": vars(context)
        }
    )

    return {
        "requestId": event["requestId"],
        "status": "success",
        "fragment": fragment,
        "errorMessage": "test-error message",
    }
