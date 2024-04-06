import json
from http import HTTPStatus


def make_response(status_code: int, message: str):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": {"status_code": status_code, "message": message},
    }


def handler(event, context):
    print(json.dumps(event))
    path: str = event["requestContext"]["http"].get("path", "")
    status_code = path.split("/")[-1]
    if not status_code.isdigit() or int(status_code) not in list(HTTPStatus):
        return make_response(HTTPStatus.BAD_REQUEST, f"No valid status found at end of path {path}")
    return make_response(int(status_code), "")
