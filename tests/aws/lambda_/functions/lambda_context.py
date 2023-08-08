def handler(event, context):
    print(event)
    print(context.aws_request_id)

    if event.get("fail"):
        raise Exception("Intentional failure")

    return context.aws_request_id
