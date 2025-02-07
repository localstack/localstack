from botocore.client import BaseClient

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.stream import SqsBuilder, StreamClient

DEFAULT_STREAMS_URL = "http://localhost:4195"


class StreamManager:
    stream_client: StreamClient
    aws_client: BaseClient

    def __init__(self):
        self.stream_client = StreamClient(DEFAULT_STREAMS_URL)

    def create_sqs_stream(self, esm_config: EventSourceMappingConfiguration):
        sqs_config = SqsBuilder().build(esm_config)

        uuid = esm_config["UUID"]
        assert self.stream_client.create_stream(uuid, sqs_config)

    def get_stream(self, id: str):
        return self.stream_client.get_stream(id)
