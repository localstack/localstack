import logging

from localstack.aws import handlers
from localstack.aws.api import RequestContext, ServiceRequest, ServiceResponse, handler
from localstack.aws.api.dynamodbstreams import (
    DescribeStreamInput,
    DescribeStreamOutput,
    DynamodbstreamsApi,
    GetRecordsInput,
    GetRecordsOutput,
    GetShardIteratorInput,
    GetShardIteratorOutput,
    ListStreamsInput,
    ListStreamsOutput,
)
from localstack.services.dynamodb.server import DynamodbServer
from localstack.services.dynamodb.utils import modify_ddblocal_arns
from localstack.services.dynamodb.v2.provider import DynamoDBProvider
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)


class DynamoDBStreamsProvider(DynamodbstreamsApi, ServiceLifecycleHook):
    def __init__(self):
        self.server = DynamodbServer.get()

    def on_after_init(self):
        # add response processor specific to ddblocal
        handlers.modify_service_response.append(self.service, modify_ddblocal_arns)

    def forward_request(
        self, context: RequestContext, service_request: ServiceRequest = None
    ) -> ServiceResponse:
        """
        Forward a request to DynamoDB Local.
        """
        DynamoDBProvider.prepare_request_headers(
            context.request.headers, account_id=context.account_id, region_name=context.region
        )
        return self.server.proxy(context, service_request)

    def modify_stream_arn_for_ddb_local(self, stream_arn: str) -> str:
        parsed_arn = parse_arn(stream_arn)

        return f"arn:aws:dynamodb:ddblocal:000000000000:{parsed_arn['resource']}"

    @handler("DescribeStream", expand=False)
    def describe_stream(
        self,
        context: RequestContext,
        payload: DescribeStreamInput,
    ) -> DescribeStreamOutput:
        request = payload.copy()
        request["StreamArn"] = self.modify_stream_arn_for_ddb_local(request.get("StreamArn", ""))
        return self.forward_request(context, request)

    @handler("GetRecords", expand=False)
    def get_records(self, context: RequestContext, payload: GetRecordsInput) -> GetRecordsOutput:
        request = payload.copy()
        request["ShardIterator"] = self.modify_stream_arn_for_ddb_local(
            request.get("ShardIterator", "")
        )
        return self.forward_request(context, request)

    @handler("GetShardIterator", expand=False)
    def get_shard_iterator(
        self, context: RequestContext, payload: GetShardIteratorInput
    ) -> GetShardIteratorOutput:
        request = payload.copy()
        request["StreamArn"] = self.modify_stream_arn_for_ddb_local(request.get("StreamArn", ""))
        return self.forward_request(context, request)

    @handler("ListStreams", expand=False)
    def list_streams(self, context: RequestContext, payload: ListStreamsInput) -> ListStreamsOutput:
        # TODO: look into `ExclusiveStartStreamArn` param
        return self.forward_request(context, payload)
