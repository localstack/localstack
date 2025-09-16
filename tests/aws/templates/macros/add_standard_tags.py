def handler(event, context):
    fragment = add_standard_attributes(event["fragment"])

    return {"requestId": event["requestId"], "status": "success", "fragment": fragment}


def add_standard_attributes(fragment):
    fragment["Tags"] = {"MacroAdded": "True"}

    return fragment
