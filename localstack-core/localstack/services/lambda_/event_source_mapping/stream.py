import logging
import os
from typing import Any, Dict, TypedDict

import requests
import yaml

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.utils.aws.arns import (
    sqs_queue_url_for_arn,
)
from localstack.utils.files import load_file

LOG = logging.getLogger(__name__)

THIS_FOLDER = os.path.dirname(__file__)
SQS_TEMPLATE = os.path.join(THIS_FOLDER, "sqs_template.yml")


def load_sqs_template() -> Dict[str, Any]:
    result = yaml.safe_load(load_file(SQS_TEMPLATE))
    return result


class Config(TypedDict):
    input: dict
    pipeline: dict
    output: dict
    buffer: dict


class Stream(TypedDict):
    active: bool
    uptime: float
    uptime_str: str
    config: dict


Streams = Dict[str, Stream]


class Builder:
    def build(self, esm_config: EventSourceMappingConfiguration) -> Config:
        pass


class SqsBuilder(Builder):
    def build(self, esm_config: EventSourceMappingConfiguration) -> Config:
        event_source_arn = esm_config["EventSourceArn"]
        function_arn = esm_config["FunctionArn"]

        queue_url = sqs_queue_url_for_arn(event_source_arn)
        if not queue_url:
            raise Exception("no queue URL found")

        bento_config = load_sqs_template()

        bento_config["input"]["aws_sqs"]["url"] = queue_url
        bento_config["pipeline"]["processors"][0]["aws_lambda"]["function"] = function_arn

        return Config(bento_config)


class StreamClient:
    url: str

    def __init__(self, url: str):
        self.url = url

    def is_ready(self) -> bool:
        response = requests.get(f"{self.url}/ready")
        return response.ok

    def list_streams(self) -> Streams:
        response = requests.get(f"{self.url}/streams")
        if not response.ok:
            LOG.error("No streams found")

        try:
            response_body = response.json()
        except requests.exceptions.JSONDecodeError as e:
            LOG.error("Failed to retrieve streams: %s", e)

        if not isinstance(response_body, dict):
            return {}

        return Streams(response_body)

    def get_stream(self, id: str) -> Stream:
        response = requests.get(f"{self.url}/streams{id}")
        if not response.ok:
            LOG.error("No streams found")

        try:
            response_body = response.json()
        except requests.exceptions.JSONDecodeError as e:
            LOG.error("Failed to retrieve streams: %s", e)

        if not isinstance(response_body, dict):
            return {}

        return Stream(response_body)

    def create_stream(self, id: str, config: Config) -> bool:
        response = requests.post(
            f"{self.url}/streams/{id}", json=config, headers={"Content-Type": "application/json"}
        )

        if not response.ok:
            LOG.error("Failed to create new stream %s.", id)
            return False

        return True

    def delete_stream(self, id: str) -> bool:
        response = requests.delete(f"{self.url}/streams/{id}")

        if not response.ok:
            LOG.error("Failed to delete stream %s.", id)
            return False

        return True
