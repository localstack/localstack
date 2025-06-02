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
    shard_to_region: dict[str, str]
    """Map a shard iterator to the originating region. This is used in case of replica tables, as LocalStack keeps the
    data in one region only, redirecting all the requests from replica regions."""

    def __init__(self):
        self.server = DynamodbServer.get()
        self.shard_to_region = {}

    def on_after_init(self):
        # add response processor specific to ddblocal
        handlers.modify_service_response.append(self.service, modify_ddblocal_arns)

    def on_before_start(self):
        self.server.start_dynamodb()

    def _forward_request(
        self, context: RequestContext, region: str | None, service_request: ServiceRequest
    ) -> ServiceResponse:
        """
        Modify the context region and then forward request to DynamoDB Local.

        This is used for operations impacted by global tables. In LocalStack, a single copy of global table
        is kept, and any requests to replicated tables are forwarded to this original table.
        """
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
        request = payload.copy()
        request["ShardIterator"] = self.modify_stream_arn_for_ddb_local(
            request.get("ShardIterator", "")
        )
        region = self.shard_to_region.pop(request["ShardIterator"], None)
        response = self._forward_request(context=context, region=region, service_request=request)
        # Similar as the logic in GetShardIterator, we need to track the originating region when we get the
        # NextShardIterator in the results.
        if (
            region
            and region != context.region
            and (next_shard := response.get("NextShardIterator"))
        ):
            self.shard_to_region[next_shard] = region
        return response

    @handler("GetShardIterator", expand=False)
    def get_shard_iterator(
        self, context: RequestContext, payload: GetShardIteratorInput
    ) -> GetShardIteratorOutput:
        global_table_region = get_original_region(context=context, stream_arn=payload["StreamArn"])
        request = payload.copy()
        request["StreamArn"] = self.modify_stream_arn_for_ddb_local(request.get("StreamArn", ""))
        response = self._forward_request(
            context=context, service_request=request, region=global_table_region
        )

        # In case of a replica table, we need to keep track of the real region originating the shard iterator.
        # This region will be later used in GetRecords to redirect to the originating region, holding the data.
        if global_table_region != context.region and (
            shard_iterator := response.get("ShardIterator")
        ):
            self.shard_to_region[shard_iterator] = global_table_region
        return response

    @handler("ListStreams", expand=False)
    def list_streams(self, context: RequestContext, payload: ListStreamsInput) -> ListStreamsOutput:
        global_table_region = get_original_region(
            context=context, stream_arn=payload.get("TableName")
        )
        # TODO: look into `ExclusiveStartStreamArn` param
        return self._forward_request(
            context=context, service_request=payload, region=global_table_region
        )
