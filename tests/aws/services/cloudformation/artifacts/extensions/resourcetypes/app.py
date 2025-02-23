import logging

import boto3


class CloudWatchLogHandler(logging.Handler):
    def __init__(self, log_group: str, logs_client, *args, **kwargs):
        self.log_group = log_group
        self.logs_client = logs_client
        super().__init__(*args, **kwargs)

    def emit(self, record: logging.LogRecord):
        pass


def create_boto_session(input: dict, region: str | None = None) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=input["accessKeyId"],
        aws_secret_access_key=input["secretAccessKey"],
        aws_session_token=input["sessionToken"],
        region_name=region,
    )


def handler(event, ctx):
    # set up logging
    # caller_credentials = event["requestData"]["callerCredentials"]
    # caller_session = create_boto_session(caller_credentials)
    provider_credentials = event["requestData"]["providerCredentials"]
    provider_session = create_boto_session(provider_credentials)

    if log_group := event["requestData"].get("providerLogGroupName"):
        logs_client = provider_session.client("logs")
        log_handler = CloudWatchLogHandler(log_group, logs_client)
        logging.getLogger().addHandler(log_handler)

    # LOG = logging.getLogger(__name__)

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
