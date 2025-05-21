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
from localstack.services.dynamodb.v2.provider import DynamoDBProvider, modify_context_region
from localstack.services.dynamodbstreams.dynamodbstreams_api import get_original_region
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import parse_arn

LOG = logging.getLogger(__name__)


class DynamoDBStreamsProvider(DynamodbstreamsApi, ServiceLifecycleHook):
    def __init__(self):
        self.server = DynamodbServer.get()

    def on_after_init(self):
        # add response processor specific to ddblocal
        handlers.modify_service_response.append(self.service, modify_ddblocal_arns)

    def on_before_start(self):
        self.server.start_dynamodb()

    def _forward_request(
        self, context: RequestContext, region: str | None, service_request: ServiceRequest
    ) -> ServiceResponse:
        if region:
            with modify_context_region(context, region):
                return self.forward_request(context, service_request=service_request)
        return self.forward_request(context, service_request=service_request)

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
        global_table_region = get_original_region(context=context, stream_arn=payload["StreamArn"])
        request = payload.copy()
        request["StreamArn"] = self.modify_stream_arn_for_ddb_local(request.get("StreamArn", ""))
        return self._forward_request(
            context=context, service_request=request, region=global_table_region
        )

    @handler("GetRecords", expand=False)
    def get_records(self, context: RequestContext, payload: GetRecordsInput) -> GetRecordsOutput:
        # Limitation note: with this current implementation, we are not able to get the records from a stream of a
        # replicated table. To do so, we would need to kept track of the originating region when we emit a ShardIterator
        # (see `GetShardIterator`) in order to forward the request to the region actually holding the stream data.

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
        global_table_region = get_original_region(context=context, stream_arn=payload["TableName"])
        # TODO: look into `ExclusiveStartStreamArn` param
        return self._forward_request(
            context=context, service_request=payload, region=global_table_region
        )
