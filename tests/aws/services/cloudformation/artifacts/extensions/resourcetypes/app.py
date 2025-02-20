import logging

LOG = logging.getLogger(__name__)


def handler(event, ctx):
    if event["action"] == "CREATE":
        return {
            "message": "",
            "callbackDelaySeconds": 0,
            "resourceModel": {"Name": "Test"},
            "status": "SUCCESS",
        }

    if event["action"] == "UPDATE":
        return {
            "message": "",
            "callbackDelaySeconds": 0,
            "resourceModel": {"Name": "Test", "Desc": "Changed"},
            "status": "SUCCESS",
        }

    if event["action"] == "DELETE":
        return {
            "message": "",
            "callbackDelaySeconds": 0,
            "resourceModel": None,
            "status": "SUCCESS",
        }
