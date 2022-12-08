import json


def handler(event, context):
    template = event["fragment"]
    params = event["params"]

    template["Resources"]["Parameter"]["Properties"]["Value"] = json.dumps(
        {
            "Params": params,
            "FunctionValue": template["Resources"]["Parameter2"]["Properties"]["Value"],
            "ValueOfRef": template["Resources"]["Parameter"]["Properties"]["Value"],
        }
    )

    return {"requestId": event["requestId"], "status": "success", "fragment": template}
