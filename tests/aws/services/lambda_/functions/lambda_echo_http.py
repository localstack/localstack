import json

DEFAULT_ARGS = {}
DEFAULT_DATA = ""
DEFAULT_DOMAIN = ""
DEFAULT_HEADERS = {}
DEFAULT_METHOD = ""
DEFAULT_ORIGIN = ""
DEFAULT_PATH = ""


def make_response(body: dict, status_code: int = 200):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": body,
    }


def handler(event, context):
    print(json.dumps(event))
    response = {
        "args": event.get("queryStringParameters", DEFAULT_ARGS),
        "data": event.get("body", DEFAULT_DATA),
        "domain": event["requestContext"].get("domainName", DEFAULT_DOMAIN),
        "headers": event.get("headers", DEFAULT_HEADERS),
        "method": event["requestContext"]["http"].get("method", DEFAULT_METHOD),
        "origin": event["requestContext"]["http"].get("sourceIp", DEFAULT_ORIGIN),
        "path": event["requestContext"]["http"].get("path", DEFAULT_PATH),
    }
    return make_response(response)
