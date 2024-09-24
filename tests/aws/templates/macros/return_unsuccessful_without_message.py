def handler(event, context):
    return {"requestId": event["requestId"], "status": "failed", "fragment": event["fragment"]}
