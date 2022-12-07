import json


def handler(event, context):
    fragment = event["fragment"]

    fragment["Resources"]["Parameter"]["Properties"]["Value"] = json.dumps(
        {
            "Event": event,
        }
    )

    return {"requestId": event["requestId"], "status": "success", "fragment": fragment}
