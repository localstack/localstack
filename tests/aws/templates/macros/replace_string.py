def handler(event, context):
    parameters = event.get("params", {})
    fragment = walk(event["fragment"], parameters)

    resp = {"requestId": event["requestId"], "status": "success", "fragment": fragment}

    return resp


def walk(node, context):
    if isinstance(node, dict):
        return {k: walk(v, context) for k, v in node.items()}
    elif isinstance(node, list):
        return [walk(elem, context) for elem in node]
    elif isinstance(node, str) and "<replace-this>" in node:
        return node.replace("<replace-this>", f'{context.get("Input")} <replace-this>')
    else:
        return node
