def handler(event, context):
    # anything else than success is considered failed
    return {"requestId": event["requestId"], "status": "success", "fragment": "invalid"}
