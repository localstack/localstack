def handler(event, context):
    template = event["fragment"]

    # anything else than success is considered failed
    return {
        "requestId": event["requestId"],
        "status": "failed",
        "fragment": template,
        "errorMessage": "failed because it is a test",
    }
