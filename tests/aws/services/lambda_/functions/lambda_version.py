def handler(event, context):
    result = {
        "version_id": "%s",
        "invoked_arn": context.invoked_function_arn,
        "version_from_ctx": context.function_version,
    }
    print(result)
    return result
