import json
import logging
import os
import random
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from operator import itemgetter
from typing import Dict, Optional

import requests
import werkzeug

from localstack import config
from localstack.aws import handlers
from localstack.aws.api import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceResponse,
    handler,
)
from localstack.aws.api.dynamodb import (
    BatchExecuteStatementOutput,
    BatchGetItemOutput,
    BatchGetRequestMap,
    BatchWriteItemInput,
    BatchWriteItemOutput,
    BillingMode,
    ContinuousBackupsDescription,
    ContinuousBackupsStatus,
    CreateGlobalTableOutput,
    CreateTableInput,
    CreateTableOutput,
    DeleteItemInput,
    DeleteItemOutput,
    DeleteRequest,
    DeleteTableOutput,
    DescribeContinuousBackupsOutput,
    DescribeGlobalTableOutput,
    DescribeKinesisStreamingDestinationOutput,
    DescribeTableOutput,
    DescribeTimeToLiveOutput,
    DestinationStatus,
    DynamodbApi,
    EnableKinesisStreamingConfiguration,
    ExecuteStatementInput,
    ExecuteStatementOutput,
    ExecuteTransactionInput,
    ExecuteTransactionOutput,
    GetItemInput,
    GetItemOutput,
    GlobalTableAlreadyExistsException,
    GlobalTableNotFoundException,
    KinesisStreamingDestinationOutput,
    ListGlobalTablesOutput,
    ListTablesInputLimit,
    ListTablesOutput,
    ListTagsOfResourceOutput,
    NextTokenString,
    PartiQLBatchRequest,
    PointInTimeRecoveryDescription,
    PointInTimeRecoverySpecification,
    PointInTimeRecoveryStatus,
    PositiveIntegerObject,
    ProvisionedThroughputExceededException,
    PutItemInput,
    PutItemOutput,
    PutRequest,
    QueryInput,
    QueryOutput,
    RegionName,
    ReplicaDescription,
    ReplicaList,
    ReplicaStatus,
    ReplicaUpdateList,
    ResourceArnString,
    ResourceInUseException,
    ResourceNotFoundException,
    ReturnConsumedCapacity,
    ScanInput,
    ScanOutput,
    StreamArn,
    TableDescription,
    TableName,
    TagKeyList,
    TagList,
    TimeToLiveSpecification,
    TransactGetItemList,
    TransactGetItemsOutput,
    TransactWriteItemsInput,
    TransactWriteItemsOutput,
    UpdateContinuousBackupsOutput,
    UpdateGlobalTableOutput,
    UpdateItemInput,
    UpdateItemOutput,
    UpdateTableInput,
    UpdateTableOutput,
    UpdateTimeToLiveOutput,
    WriteRequest,
)
from localstack.aws.connect import connect_to
from localstack.constants import (
    AUTH_CREDENTIAL_REGEX,
    AWS_REGION_US_EAST_1,
    INTERNAL_AWS_SECRET_ACCESS_KEY,
)
from localstack.http import Request, Response, route
from localstack.services.dynamodb.models import (
    DynamoDBStore,
    StreamRecord,
    dynamodb_stores,
)
from localstack.services.dynamodb.server import DynamodbServer
from localstack.services.dynamodb.utils import (
    SchemaExtractor,
    get_ddb_access_key,
    modify_ddblocal_arns,
)
from localstack.services.dynamodbstreams.models import dynamodbstreams_stores
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import AssetDirectory, StateVisitor
from localstack.utils.aws import arns
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    get_partition,
)
from localstack.utils.aws.aws_stack import get_valid_regions_for_service
from localstack.utils.aws.request_context import (
    extract_account_id_from_headers,
    extract_region_from_headers,
)
from localstack.utils.collections import select_attributes, select_from_typed_dict
from localstack.utils.common import short_uid, to_bytes
from localstack.utils.json import canonical_json
from localstack.utils.scheduler import Scheduler
from localstack.utils.strings import long_uid, to_str
from localstack.utils.threads import FuncThread, start_thread

# set up logger
LOG = logging.getLogger(__name__)

# action header prefix
ACTION_PREFIX = "DynamoDB_20120810."

# list of actions subject to throughput limitations
READ_THROTTLED_ACTIONS = [
    "GetItem",
    "Query",
    "Scan",
    "TransactGetItems",
    "BatchGetItem",
]
WRITE_THROTTLED_ACTIONS = [
    "PutItem",
    "BatchWriteItem",
    "UpdateItem",
    "DeleteItem",
    "TransactWriteItems",
]
THROTTLED_ACTIONS = READ_THROTTLED_ACTIONS + WRITE_THROTTLED_ACTIONS

MANAGED_KMS_KEYS = {}


def dynamodb_table_exists(table_name: str, client=None) -> bool:
    client = client or connect_to().dynamodb
    paginator = client.get_paginator("list_tables")
    pages = paginator.paginate(PaginationConfig={"PageSize": 100})
    table_name = to_str(table_name)
    return any(table_name in page["TableNames"] for page in pages)


class SSEUtils:
    """Utils for server-side encryption (SSE)"""

    @classmethod
    def get_sse_kms_managed_key(cls, account_id: str, region_name: str):
        from localstack.services.kms import provider

        existing_key = MANAGED_KMS_KEYS.get(region_name)
        if existing_key:
            return existing_key
        kms_client = connect_to(
            aws_access_key_id=account_id,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        ).kms
        key_data = kms_client.create_key(
            Description="Default key that protects my DynamoDB data when no other key is defined"
        )
        key_id = key_data["KeyMetadata"]["KeyId"]

        provider.set_key_managed(key_id, account_id, region_name)
        MANAGED_KMS_KEYS[region_name] = key_id
        return key_id

    @classmethod
    def get_sse_description(cls, account_id: str, region_name: str, data):
        if data.get("Enabled"):
            kms_master_key_id = data.get("KMSMasterKeyId")
            if not kms_master_key_id:
                # this is of course not the actual key for dynamodb, just a better, since existing, mock
                kms_master_key_id = cls.get_sse_kms_managed_key(account_id, region_name)
            kms_master_key_id = arns.kms_key_arn(kms_master_key_id, account_id, region_name)
            return {
                "Status": "ENABLED",
                "SSEType": "KMS",  # no other value is allowed here
                "KMSMasterKeyArn": kms_master_key_id,
            }
        return {}


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(code="ValidationException", status_code=400, message=message)


def get_store(account_id: str, region_name: str) -> DynamoDBStore:
    # special case: AWS NoSQL Workbench sends "localhost" as region - replace with proper region here
    region_name = DynamoDBProvider.ddb_region_name(region_name)
    return dynamodb_stores[account_id][region_name]


@contextmanager
def modify_context_region(context: RequestContext, region: str):
    """
    Context manager that modifies the region of a `RequestContext`. At the exit, the context is restored to its
    original state.

    :param context: the context to modify
    :param region: the modified region
    :return: a modified `RequestContext`
    """
    original_region = context.region
    original_authorization = context.request.headers.get("Authorization")

    key = get_ddb_access_key(context.account_id, region)

    context.region = region
    context.request.headers["Authorization"] = re.sub(
        AUTH_CREDENTIAL_REGEX,
        rf"Credential={key}/\2/{region}/\4/",
        original_authorization or "",
        flags=re.IGNORECASE,
    )

    try:
        yield context
    except Exception:
        raise
    finally:
        # revert the original context
        context.region = original_region
        context.request.headers["Authorization"] = original_authorization


class DynamoDBDeveloperEndpoints:
    """
    Developer endpoints for DynamoDB
    DELETE /_aws/dynamodb/expired - delete expired items from tables with TTL enabled; return the number of expired
        items deleted
    """

    @route("/_aws/dynamodb/expired", methods=["DELETE"])
    def delete_expired_messages(self, _: Request):
        no_expired_items = delete_expired_items()
        return {"ExpiredItems": no_expired_items}


def delete_expired_items() -> int:
    """
    This utility function iterates over all stores, looks for tables with TTL enabled,
    scan such tables and delete expired items.
    """
    no_expired_items = 0
    for account_id, region_name, state in dynamodb_stores.iter_stores():
        ttl_specs = state.ttl_specifications
        client = connect_to(aws_access_key_id=account_id, region_name=region_name).dynamodb
        for table_name, ttl_spec in ttl_specs.items():
            if ttl_spec.get("Enabled", False):
                attribute_name = ttl_spec.get("AttributeName")
                current_time = int(datetime.now().timestamp())
                try:
                    result = client.scan(
                        TableName=table_name,
                        FilterExpression="#ttl <= :threshold",
                        ExpressionAttributeValues={":threshold": {"N": str(current_time)}},
                        ExpressionAttributeNames={"#ttl": attribute_name},
                    )
                    items_to_delete = result.get("Items", [])
                    no_expired_items += len(items_to_delete)
                    table_description = client.describe_table(TableName=table_name)
                    partition_key, range_key = _get_hash_and_range_key(table_description)
                    keys_to_delete = [
                        {partition_key: item.get(partition_key)}
                        if range_key is None
                        else {
                            partition_key: item.get(partition_key),
                            range_key: item.get(range_key),
                        }
                        for item in items_to_delete
                    ]
                    delete_requests = [{"DeleteRequest": {"Key": key}} for key in keys_to_delete]
                    for i in range(0, len(delete_requests), 25):
                        batch = delete_requests[i : i + 25]
                        client.batch_write_item(RequestItems={table_name: batch})
                except Exception as e:
                    LOG.warning(
                        "An error occurred when deleting expired items from table %s: %s",
                        table_name,
                        e,
                    )
    return no_expired_items


def _get_hash_and_range_key(table_description: DescribeTableOutput) -> [str, str | None]:
    key_schema = table_description.get("Table", {}).get("KeySchema", [])
    hash_key, range_key = None, None
    for key in key_schema:
        if key["KeyType"] == "HASH":
            hash_key = key["AttributeName"]
        if key["KeyType"] == "RANGE":
            range_key = key["AttributeName"]
    return hash_key, range_key


class ExpiredItemsWorker:
    """A worker that periodically computes and deletes expired items from DynamoDB tables"""

    def __init__(self) -> None:
        super().__init__()
        self.scheduler = Scheduler()
        self.thread: Optional[FuncThread] = None
        self.mutex = threading.RLock()

    def start(self):
        with self.mutex:
            if self.thread:
                return

            self.scheduler = Scheduler()
            self.scheduler.schedule(
                delete_expired_items, period=60 * 60
            )  # the background process seems slow on AWS

            def _run(*_args):
                self.scheduler.run()

            self.thread = start_thread(_run, name="ddb-remove-expired-items")

    def stop(self):
        with self.mutex:
            if self.scheduler:
                self.scheduler.close()

            if self.thread:
                self.thread.stop()

            self.thread = None
            self.scheduler = None


class DynamoDBProvider(DynamodbApi, ServiceLifecycleHook):
    server: DynamodbServer
    """The instance of the server managing the instance of DynamoDB local"""

    def __init__(self):
        self.server = self._new_dynamodb_server()
        self._expired_items_worker = ExpiredItemsWorker()
        self._router_rules = []

    def on_before_start(self):
        self.server.start_dynamodb()
        if config.DYNAMODB_REMOVE_EXPIRED_ITEMS:
            self._expired_items_worker.start()
        self._router_rules = ROUTER.add(DynamoDBDeveloperEndpoints())

    def on_before_stop(self):
        self._expired_items_worker.stop()
        ROUTER.remove(self._router_rules)

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(dynamodb_stores)
        visitor.visit(dynamodbstreams_stores)
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, self.service)))

    def on_before_state_reset(self):
        self.server.stop_dynamodb()

    def on_before_state_load(self):
        self.server.stop_dynamodb()

    def on_after_state_reset(self):
        self.server.start_dynamodb()

    @staticmethod
    def _new_dynamodb_server() -> DynamodbServer:
        return DynamodbServer.get()

    def on_after_state_load(self):
        self.server.start_dynamodb()

    def on_after_init(self):
        # add response processor specific to ddblocal
        handlers.modify_service_response.append(self.service, modify_ddblocal_arns)

        # routes for the shell ui
        ROUTER.add(
            path="/shell",
            endpoint=self.handle_shell_ui_redirect,
            methods=["GET"],
        )
        ROUTER.add(
            path="/shell/<regex('.*'):req_path>",
            endpoint=self.handle_shell_ui_request,
        )

    def _forward_request(
        self,
        context: RequestContext,
        region: str | None,
        service_request: ServiceRequest | None = None,
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
        self.check_provisioned_throughput(context.operation.name)
        self.prepare_request_headers(
            context.request.headers, account_id=context.account_id, region_name=context.region
        )
        return self.server.proxy(context, service_request)

    def get_forward_url(self, account_id: str, region_name: str) -> str:
        """Return the URL of the backend DynamoDBLocal server to forward requests to"""
        return self.server.url

    def handle_shell_ui_redirect(self, request: werkzeug.Request) -> Response:
        headers = {"Refresh": f"0; url={config.external_service_url()}/shell/index.html"}
        return Response("", headers=headers)

    def handle_shell_ui_request(self, request: werkzeug.Request, req_path: str) -> Response:
        # TODO: "DynamoDB Local Web Shell was deprecated with version 1.16.X and is not available any
        #  longer from 1.17.X to latest. There are no immediate plans for a new Web Shell to be introduced."
        #  -> keeping this for now, to allow configuring custom installs; should consider removing it in the future
        # https://repost.aws/questions/QUHyIzoEDqQ3iOKlUEp1LPWQ#ANdBm9Nz9TRf6VqR3jZtcA1g
        req_path = f"/{req_path}" if not req_path.startswith("/") else req_path
        account_id = extract_account_id_from_headers(request.headers)
        region_name = extract_region_from_headers(request.headers)
        url = f"{self.get_forward_url(account_id, region_name)}/shell{req_path}"
        result = requests.request(
            method=request.method, url=url, headers=request.headers, data=request.data
        )
        return Response(result.content, headers=dict(result.headers), status=result.status_code)

    #
    # Table ops
    #

    @handler("CreateTable", expand=False)
    def create_table(
        self,
        context: RequestContext,
        create_table_input: CreateTableInput,
    ) -> CreateTableOutput:
        table_name = create_table_input["TableName"]

        # Return this specific error message to keep parity with AWS
        if self.table_exists(context.account_id, context.region, table_name):
            raise ResourceInUseException(f"Table already exists: {table_name}")

        billing_mode = create_table_input.get("BillingMode")
        provisioned_throughput = create_table_input.get("ProvisionedThroughput")
        if billing_mode == BillingMode.PAY_PER_REQUEST and provisioned_throughput is not None:
            raise ValidationException(
                "One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits can be "
                "specified when BillingMode is PAY_PER_REQUEST"
            )

        result = self.forward_request(context)

        table_description = result["TableDescription"]
        table_description["TableArn"] = table_arn = self.fix_table_arn(
            context.account_id, context.region, table_description["TableArn"]
        )

        backend = get_store(context.account_id, context.region)
        backend.table_definitions[table_name] = table_definitions = dict(create_table_input)
        backend.TABLE_REGION[table_name] = context.region

        if "TableId" not in table_definitions:
            table_definitions["TableId"] = long_uid()

        if "SSESpecification" in table_definitions:
            sse_specification = table_definitions.pop("SSESpecification")
            table_definitions["SSEDescription"] = SSEUtils.get_sse_description(
                context.account_id, context.region, sse_specification
            )

        if table_definitions:
            table_content = result.get("Table", {})
            table_content.update(table_definitions)
            table_description.update(table_content)

        if "TableClass" in table_definitions:
            table_class = table_description.pop("TableClass", None) or table_definitions.pop(
                "TableClass"
            )
            table_description["TableClassSummary"] = {"TableClass": table_class}

        tags = table_definitions.pop("Tags", [])
        if tags:
            get_store(context.account_id, context.region).TABLE_TAGS[table_arn] = {
                tag["Key"]: tag["Value"] for tag in tags
            }

        # remove invalid attributes from result
        table_description.pop("Tags", None)
        table_description.pop("BillingMode", None)

        return result

    def delete_table(
        self, context: RequestContext, table_name: TableName, **kwargs
    ) -> DeleteTableOutput:
        global_table_region = self.get_global_table_region(context, table_name)

        # Limitation note: On AWS, for a replicated table, if the source table is deleted, the replicated tables continue to exist.
        # This is not the case for LocalStack, where all replicated tables will also be removed if source is deleted.

        result = self._forward_request(context=context, region=global_table_region)

        table_arn = result.get("TableDescription", {}).get("TableArn")
        table_arn = self.fix_table_arn(context.account_id, context.region, table_arn)

        store = get_store(context.account_id, context.region)
        store.TABLE_TAGS.pop(table_arn, None)
        store.REPLICAS.pop(table_name, None)

        return result

    def describe_table(
        self, context: RequestContext, table_name: TableName, **kwargs
    ) -> DescribeTableOutput:
        global_table_region = self.get_global_table_region(context, table_name)

        result = self._forward_request(context=context, region=global_table_region)
        table_description: TableDescription = result["Table"]

        # Update table properties from LocalStack stores
        if table_props := get_store(context.account_id, context.region).table_properties.get(
            table_name
        ):
            table_description.update(table_props)

        store = get_store(context.account_id, context.region)

        # Update replication details
        replicas: Dict[RegionName, ReplicaDescription] = store.REPLICAS.get(table_name, {})

        replica_description_list = []

        if global_table_region != context.region:
            replica_description_list.append(
                ReplicaDescription(
                    RegionName=global_table_region, ReplicaStatus=ReplicaStatus.ACTIVE
                )
            )

        for replica_region, replica_description in replicas.items():
            # The replica in the region being queried must not be returned
            if replica_region != context.region:
                replica_description_list.append(replica_description)

        table_description.update({"Replicas": replica_description_list})

        # update only TableId and SSEDescription if present
        if table_definitions := store.table_definitions.get(table_name):
            for key in ["TableId", "SSEDescription"]:
                if table_definitions.get(key):
                    table_description[key] = table_definitions[key]
            if "TableClass" in table_definitions:
                table_description["TableClassSummary"] = {
                    "TableClass": table_definitions["TableClass"]
                }

        return DescribeTableOutput(
            Table=select_from_typed_dict(TableDescription, table_description)
        )

    @handler("UpdateTable", expand=False)
    def update_table(
        self, context: RequestContext, update_table_input: UpdateTableInput
    ) -> UpdateTableOutput:
        table_name = update_table_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        try:
            result = self._forward_request(context=context, region=global_table_region)
        except CommonServiceException as exc:
            # DynamoDBLocal refuses to update certain table params and raises.
            # But we still need to update this info in LocalStack stores
            if not (exc.code == "ValidationException" and exc.message == "Nothing to update"):
                raise

            if table_class := update_table_input.get("TableClass"):
                table_definitions = get_store(
                    context.account_id, context.region
                ).table_definitions.setdefault(table_name, {})
                table_definitions["TableClass"] = table_class

            if replica_updates := update_table_input.get("ReplicaUpdates"):
                store = get_store(context.account_id, global_table_region)

                # Dict with source region to set of replicated regions
                replicas: Dict[RegionName, ReplicaDescription] = store.REPLICAS.get(table_name, {})

                for replica_update in replica_updates:
                    for key, details in replica_update.items():
                        # Replicated region
                        target_region = details.get("RegionName")

                        # Check if replicated region is valid
                        if target_region not in get_valid_regions_for_service("dynamodb"):
                            raise ValidationException(f"Region {target_region} is not supported")

                        match key:
                            case "Create":
                                if target_region in replicas.keys():
                                    raise ValidationException(
                                        f"Failed to create a the new replica of table with name: '{table_name}' because one or more replicas already existed as tables."
                                    )
                                replicas[target_region] = ReplicaDescription(
                                    RegionName=target_region,
                                    KMSMasterKeyId=details.get("KMSMasterKeyId"),
                                    ProvisionedThroughputOverride=details.get(
                                        "ProvisionedThroughputOverride"
                                    ),
                                    GlobalSecondaryIndexes=details.get("GlobalSecondaryIndexes"),
                                    ReplicaStatus=ReplicaStatus.ACTIVE,
                                )
                            case "Delete":
                                try:
                                    replicas.pop(target_region)
                                except KeyError:
                                    raise ValidationException(
                                        "Update global table operation failed because one or more replicas were not part of the global table."
                                    )

                store.REPLICAS[table_name] = replicas

            # update response content
            SchemaExtractor.invalidate_table_schema(
                table_name, context.account_id, global_table_region
            )

            schema = SchemaExtractor.get_table_schema(
                table_name, context.account_id, global_table_region
            )

            if sse_specification_input := update_table_input.get("SSESpecification"):
                # If SSESpecification is changed, update store and return the 'UPDATING' status in the response
                table_definition = get_store(
                    context.account_id, context.region
                ).table_definitions.setdefault(table_name, {})
                if not sse_specification_input["Enabled"]:
                    table_definition.pop("SSEDescription", None)
                    schema["Table"]["SSEDescription"]["Status"] = "UPDATING"

            return UpdateTableOutput(TableDescription=schema["Table"])

        SchemaExtractor.invalidate_table_schema(table_name, context.account_id, global_table_region)

        return result

    def list_tables(
        self,
        context: RequestContext,
        exclusive_start_table_name: TableName = None,
        limit: ListTablesInputLimit = None,
        **kwargs,
    ) -> ListTablesOutput:
        response = self.forward_request(context)

        # Add replicated tables
        replicas = get_store(context.account_id, context.region).REPLICAS
        for replicated_table, replications in replicas.items():
            for replica_region, replica_description in replications.items():
                if context.region == replica_region:
                    response["TableNames"].append(replicated_table)

        return response

    #
    # Item ops
    #

    @handler("PutItem", expand=False)
    def put_item(self, context: RequestContext, put_item_input: PutItemInput) -> PutItemOutput:
        table_name = put_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        return self._forward_request(context=context, region=global_table_region)

    @handler("DeleteItem", expand=False)
    def delete_item(
        self,
        context: RequestContext,
        delete_item_input: DeleteItemInput,
    ) -> DeleteItemOutput:
        table_name = delete_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        return self._forward_request(context=context, region=global_table_region)

    @handler("UpdateItem", expand=False)
    def update_item(
        self,
        context: RequestContext,
        update_item_input: UpdateItemInput,
    ) -> UpdateItemOutput:
        # TODO: UpdateItem is harder to use ReturnValues for Streams, because it needs the Before and After images.
        table_name = update_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)

        return self._forward_request(context=context, region=global_table_region)

    @handler("GetItem", expand=False)
    def get_item(self, context: RequestContext, get_item_input: GetItemInput) -> GetItemOutput:
        table_name = get_item_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)
        result = self._forward_request(context=context, region=global_table_region)
        self.fix_consumed_capacity(get_item_input, result)
        return result

    #
    # Queries
    #

    @handler("Query", expand=False)
    def query(self, context: RequestContext, query_input: QueryInput) -> QueryOutput:
        index_name = query_input.get("IndexName")
        if index_name:
            if not is_index_query_valid(context.account_id, context.region, query_input):
                raise ValidationException(
                    "One or more parameter values were invalid: Select type ALL_ATTRIBUTES "
                    "is not supported for global secondary index id-index because its projection "
                    "type is not ALL",
                )

        table_name = query_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)
        result = self._forward_request(context=context, region=global_table_region)
        self.fix_consumed_capacity(query_input, result)
        return result

    @handler("Scan", expand=False)
    def scan(self, context: RequestContext, scan_input: ScanInput) -> ScanOutput:
        table_name = scan_input["TableName"]
        global_table_region = self.get_global_table_region(context, table_name)
        result = self._forward_request(context=context, region=global_table_region)
        return result

    #
    # Batch ops
    #

    @handler("BatchWriteItem", expand=False)
    def batch_write_item(
        self,
        context: RequestContext,
        batch_write_item_input: BatchWriteItemInput,
    ) -> BatchWriteItemOutput:
        # TODO: add global table support
        # UnprocessedItems should have the same format as RequestItems
        unprocessed_items = {}
        request_items = batch_write_item_input["RequestItems"]

        for table_name, items in sorted(request_items.items(), key=itemgetter(0)):
            for request in items:
                request: WriteRequest
                for key, inner_request in request.items():
                    inner_request: PutRequest | DeleteRequest
                    if self.should_throttle("BatchWriteItem"):
                        unprocessed_items_for_table = unprocessed_items.setdefault(table_name, [])
                        unprocessed_items_for_table.append(request)

        try:
            result = self.forward_request(context)
        except CommonServiceException as e:
            # TODO: validate if DynamoDB still raises `One of the required keys was not given a value`
            # for now, replace with the schema error validation
            if e.message == "One of the required keys was not given a value":
                raise ValidationException("The provided key element does not match the schema")
            raise e

        # TODO: should unprocessed item which have mutated by `prepare_batch_write_item_records` be returned
        for table_name, unprocessed_items_in_table in unprocessed_items.items():
            unprocessed: dict = result["UnprocessedItems"]
            result_unprocessed_table = unprocessed.setdefault(table_name, [])

            # add the Unprocessed items to the response
            # TODO: check before if the same request has not been Unprocessed by DDB local already?
            # those might actually have been processed? shouldn't we remove them from the proxied request?
            for request in unprocessed_items_in_table:
                result_unprocessed_table.append(request)

            # remove any table entry if it's empty
            result["UnprocessedItems"] = {k: v for k, v in unprocessed.items() if v}

        return result

    @handler("BatchGetItem")
    def batch_get_item(
        self,
        context: RequestContext,
        request_items: BatchGetRequestMap,
        return_consumed_capacity: ReturnConsumedCapacity = None,
        **kwargs,
    ) -> BatchGetItemOutput:
        # TODO: add global table support
        return self.forward_request(context)

    #
    # Transactions
    #

    @handler("TransactWriteItems", expand=False)
    def transact_write_items(
        self,
        context: RequestContext,
        transact_write_items_input: TransactWriteItemsInput,
    ) -> TransactWriteItemsOutput:
        # TODO: add global table support
        client_token: str | None = transact_write_items_input.get("ClientRequestToken")

        if client_token:
            # we sort the payload since identical payload but with different order could cause
            # IdempotentParameterMismatchException error if a client token is provided
            context.request.data = to_bytes(canonical_json(json.loads(context.request.data)))

        return self.forward_request(context)

    @handler("TransactGetItems", expand=False)
    def transact_get_items(
        self,
        context: RequestContext,
        transact_items: TransactGetItemList,
        return_consumed_capacity: ReturnConsumedCapacity = None,
    ) -> TransactGetItemsOutput:
        return self.forward_request(context)

    @handler("ExecuteTransaction", expand=False)
    def execute_transaction(
        self, context: RequestContext, execute_transaction_input: ExecuteTransactionInput
    ) -> ExecuteTransactionOutput:
        result = self.forward_request(context)
        return result

    @handler("ExecuteStatement", expand=False)
    def execute_statement(
        self,
        context: RequestContext,
        execute_statement_input: ExecuteStatementInput,
    ) -> ExecuteStatementOutput:
        # TODO: this operation is still really slow with streams enabled
        #  find a way to make it better, same way as the other operations, by using returnvalues
        # see https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
        return self.forward_request(context)

    #
    # Tags
    #

    def tag_resource(
        self, context: RequestContext, resource_arn: ResourceArnString, tags: TagList, **kwargs
    ) -> None:
        table_tags = get_store(context.account_id, context.region).TABLE_TAGS
        if resource_arn not in table_tags:
            table_tags[resource_arn] = {}
        table_tags[resource_arn].update({tag["Key"]: tag["Value"] for tag in tags})

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        for tag_key in tag_keys or []:
            get_store(context.account_id, context.region).TABLE_TAGS.get(resource_arn, {}).pop(
                tag_key, None
            )

    def list_tags_of_resource(
        self,
        context: RequestContext,
        resource_arn: ResourceArnString,
        next_token: NextTokenString = None,
        **kwargs,
    ) -> ListTagsOfResourceOutput:
        result = [
            {"Key": k, "Value": v}
            for k, v in get_store(context.account_id, context.region)
            .TABLE_TAGS.get(resource_arn, {})
            .items()
        ]
        return ListTagsOfResourceOutput(Tags=result)

    #
    # TTLs
    #

    def describe_time_to_live(
        self, context: RequestContext, table_name: TableName, **kwargs
    ) -> DescribeTimeToLiveOutput:
        if not self.table_exists(context.account_id, context.region, table_name):
            raise ResourceNotFoundException(
                f"Requested resource not found: Table: {table_name} not found"
            )

        backend = get_store(context.account_id, context.region)
        ttl_spec = backend.ttl_specifications.get(table_name)

        result = {"TimeToLiveStatus": "DISABLED"}
        if ttl_spec:
            if ttl_spec.get("Enabled"):
                ttl_status = "ENABLED"
            else:
                ttl_status = "DISABLED"
            result = {
                "AttributeName": ttl_spec.get("AttributeName"),
                "TimeToLiveStatus": ttl_status,
            }

        return DescribeTimeToLiveOutput(TimeToLiveDescription=result)

    def update_time_to_live(
        self,
        context: RequestContext,
        table_name: TableName,
        time_to_live_specification: TimeToLiveSpecification,
        **kwargs,
    ) -> UpdateTimeToLiveOutput:
        if not self.table_exists(context.account_id, context.region, table_name):
            raise ResourceNotFoundException(
                f"Requested resource not found: Table: {table_name} not found"
            )

        # TODO: TTL status is maintained/mocked but no real expiry is happening for items
        backend = get_store(context.account_id, context.region)
        backend.ttl_specifications[table_name] = time_to_live_specification
        return UpdateTimeToLiveOutput(TimeToLiveSpecification=time_to_live_specification)

    #
    # Global tables
    #

    def create_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replication_group: ReplicaList,
        **kwargs,
    ) -> CreateGlobalTableOutput:
        global_tables: Dict = get_store(context.account_id, context.region).GLOBAL_TABLES
        if global_table_name in global_tables:
            raise GlobalTableAlreadyExistsException("Global table with this name already exists")
        replication_group = [grp.copy() for grp in replication_group or []]
        data = {"GlobalTableName": global_table_name, "ReplicationGroup": replication_group}
        global_tables[global_table_name] = data
        for group in replication_group:
            group["ReplicaStatus"] = "ACTIVE"
            group["ReplicaStatusDescription"] = "Replica active"
        return CreateGlobalTableOutput(GlobalTableDescription=data)

    def describe_global_table(
        self, context: RequestContext, global_table_name: TableName, **kwargs
    ) -> DescribeGlobalTableOutput:
        details = get_store(context.account_id, context.region).GLOBAL_TABLES.get(global_table_name)
        if not details:
            raise GlobalTableNotFoundException("Global table with this name does not exist")
        return DescribeGlobalTableOutput(GlobalTableDescription=details)

    def list_global_tables(
        self,
        context: RequestContext,
        exclusive_start_global_table_name: TableName = None,
        limit: PositiveIntegerObject = None,
        region_name: RegionName = None,
        **kwargs,
    ) -> ListGlobalTablesOutput:
        # TODO: add paging support
        result = [
            select_attributes(tab, ["GlobalTableName", "ReplicationGroup"])
            for tab in get_store(context.account_id, context.region).GLOBAL_TABLES.values()
        ]
        return ListGlobalTablesOutput(GlobalTables=result)

    def update_global_table(
        self,
        context: RequestContext,
        global_table_name: TableName,
        replica_updates: ReplicaUpdateList,
        **kwargs,
    ) -> UpdateGlobalTableOutput:
        details = get_store(context.account_id, context.region).GLOBAL_TABLES.get(global_table_name)
        if not details:
            raise GlobalTableNotFoundException("Global table with this name does not exist")
        for update in replica_updates or []:
            repl_group = details["ReplicationGroup"]
            # delete existing
            delete = update.get("Delete")
            if delete:
                details["ReplicationGroup"] = [
                    g for g in repl_group if g["RegionName"] != delete["RegionName"]
                ]
            # create new
            create = update.get("Create")
            if create:
                exists = [g for g in repl_group if g["RegionName"] == create["RegionName"]]
                if exists:
                    continue
                new_group = {
                    "RegionName": create["RegionName"],
                    "ReplicaStatus": "ACTIVE",
                    "ReplicaStatusDescription": "Replica active",
                }
                details["ReplicationGroup"].append(new_group)
        return UpdateGlobalTableOutput(GlobalTableDescription=details)

    #
    # Kinesis Streaming
    #

    def enable_kinesis_streaming_destination(
        self,
        context: RequestContext,
        table_name: TableName,
        stream_arn: StreamArn,
        enable_kinesis_streaming_configuration: EnableKinesisStreamingConfiguration = None,
        **kwargs,
    ) -> KinesisStreamingDestinationOutput:
        self.ensure_table_exists(context.account_id, context.region, table_name)

        if not kinesis_stream_exists(stream_arn=stream_arn):
            raise ValidationException("User does not have a permission to use kinesis stream")

        table_def = get_store(context.account_id, context.region).table_definitions.setdefault(
            table_name, {}
        )

        dest_status = table_def.get("KinesisDataStreamDestinationStatus")
        if dest_status not in ["DISABLED", "ENABLE_FAILED", None]:
            raise ValidationException(
                "Table is not in a valid state to enable Kinesis Streaming "
                "Destination:EnableKinesisStreamingDestination must be DISABLED or ENABLE_FAILED "
                "to perform ENABLE operation."
            )

        table_def["KinesisDataStreamDestinations"] = (
            table_def.get("KinesisDataStreamDestinations") or []
        )
        # remove the stream destination if already present
        table_def["KinesisDataStreamDestinations"] = [
            t for t in table_def["KinesisDataStreamDestinations"] if t["StreamArn"] != stream_arn
        ]
        # append the active stream destination at the end of the list
        table_def["KinesisDataStreamDestinations"].append(
            {
                "DestinationStatus": DestinationStatus.ACTIVE,
                "DestinationStatusDescription": "Stream is active",
                "StreamArn": stream_arn,
            }
        )
        table_def["KinesisDataStreamDestinationStatus"] = DestinationStatus.ACTIVE
        return KinesisStreamingDestinationOutput(
            DestinationStatus=DestinationStatus.ACTIVE, StreamArn=stream_arn, TableName=table_name
        )

    def disable_kinesis_streaming_destination(
        self,
        context: RequestContext,
        table_name: TableName,
        stream_arn: StreamArn,
        enable_kinesis_streaming_configuration: EnableKinesisStreamingConfiguration = None,
        **kwargs,
    ) -> KinesisStreamingDestinationOutput:
        self.ensure_table_exists(context.account_id, context.region, table_name)
        if not kinesis_stream_exists(stream_arn):
            raise ValidationException(
                "User does not have a permission to use kinesis stream",
            )

        table_def = get_store(context.account_id, context.region).table_definitions.setdefault(
            table_name, {}
        )

        stream_destinations = table_def.get("KinesisDataStreamDestinations")
        if stream_destinations:
            if table_def["KinesisDataStreamDestinationStatus"] == DestinationStatus.ACTIVE:
                for dest in stream_destinations:
                    if (
                        dest["StreamArn"] == stream_arn
                        and dest["DestinationStatus"] == DestinationStatus.ACTIVE
                    ):
                        dest["DestinationStatus"] = DestinationStatus.DISABLED
                        dest["DestinationStatusDescription"] = ("Stream is disabled",)
                        table_def["KinesisDataStreamDestinationStatus"] = DestinationStatus.DISABLED
                        return KinesisStreamingDestinationOutput(
                            DestinationStatus=DestinationStatus.DISABLED,
                            StreamArn=stream_arn,
                            TableName=table_name,
                        )
        raise ValidationException(
            "Table is not in a valid state to disable Kinesis Streaming Destination:"
            "DisableKinesisStreamingDestination must be ACTIVE to perform DISABLE operation."
        )

    def describe_kinesis_streaming_destination(
        self, context: RequestContext, table_name: TableName, **kwargs
    ) -> DescribeKinesisStreamingDestinationOutput:
        self.ensure_table_exists(context.account_id, context.region, table_name)

        table_def = (
            get_store(context.account_id, context.region).table_definitions.get(table_name) or {}
        )

        stream_destinations = table_def.get("KinesisDataStreamDestinations") or []
        return DescribeKinesisStreamingDestinationOutput(
            KinesisDataStreamDestinations=stream_destinations, TableName=table_name
        )

    #
    # Continuous Backups
    #

    def describe_continuous_backups(
        self, context: RequestContext, table_name: TableName, **kwargs
    ) -> DescribeContinuousBackupsOutput:
        self.get_global_table_region(context, table_name)
        store = get_store(context.account_id, context.region)
        continuous_backup_description = (
            store.table_properties.get(table_name, {}).get("ContinuousBackupsDescription")
        ) or ContinuousBackupsDescription(
            ContinuousBackupsStatus=ContinuousBackupsStatus.ENABLED,
            PointInTimeRecoveryDescription=PointInTimeRecoveryDescription(
                PointInTimeRecoveryStatus=PointInTimeRecoveryStatus.DISABLED
            ),
        )

        return DescribeContinuousBackupsOutput(
            ContinuousBackupsDescription=continuous_backup_description
        )

    def update_continuous_backups(
        self,
        context: RequestContext,
        table_name: TableName,
        point_in_time_recovery_specification: PointInTimeRecoverySpecification,
        **kwargs,
    ) -> UpdateContinuousBackupsOutput:
        self.get_global_table_region(context, table_name)

        store = get_store(context.account_id, context.region)
        pit_recovery_status = (
            PointInTimeRecoveryStatus.ENABLED
            if point_in_time_recovery_specification["PointInTimeRecoveryEnabled"]
            else PointInTimeRecoveryStatus.DISABLED
        )
        continuous_backup_description = ContinuousBackupsDescription(
            ContinuousBackupsStatus=ContinuousBackupsStatus.ENABLED,
            PointInTimeRecoveryDescription=PointInTimeRecoveryDescription(
                PointInTimeRecoveryStatus=pit_recovery_status
            ),
        )
        table_props = store.table_properties.setdefault(table_name, {})
        table_props["ContinuousBackupsDescription"] = continuous_backup_description

        return UpdateContinuousBackupsOutput(
            ContinuousBackupsDescription=continuous_backup_description
        )

    #
    # Helpers
    #

    @staticmethod
    def ddb_region_name(region_name: str) -> str:
        """Map `local` or `localhost` region to the us-east-1 region. These values are used by NoSQL Workbench."""
        # TODO: could this be somehow moved into the request handler chain?
        if region_name in ("local", "localhost"):
            region_name = AWS_REGION_US_EAST_1

        return region_name

    @staticmethod
    def table_exists(account_id: str, region_name: str, table_name: str) -> bool:
        region_name = DynamoDBProvider.ddb_region_name(region_name)

        client = connect_to(
            aws_access_key_id=account_id,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        ).dynamodb
        return dynamodb_table_exists(table_name, client)

    @staticmethod
    def ensure_table_exists(account_id: str, region_name: str, table_name: str):
        """
        Raise ResourceNotFoundException if the given table does not exist.

        :param account_id: account id
        :param region_name: region name
        :param table_name: table name
        :raise: ResourceNotFoundException if table does not exist in DynamoDB Local
        """
        if not DynamoDBProvider.table_exists(account_id, region_name, table_name):
            raise ResourceNotFoundException("Cannot do operations on a non-existent table")

    @staticmethod
    def get_global_table_region(context: RequestContext, table_name: str) -> str:
        """
        Return the table region considering that it might be a replicated table.

        Replication in LocalStack works by keeping a single copy of a table and forwarding
        requests to the region where this table exists.

        This method does not check whether the table actually exists in DDBLocal.

        :param context: request context
        :param table_name: table name
        :return: region
        """
        store = get_store(context.account_id, context.region)

        table_region = store.TABLE_REGION.get(table_name)
        replicated_at = store.REPLICAS.get(table_name, {}).keys()

        if context.region == table_region or context.region in replicated_at:
            return table_region

        return context.region

    @staticmethod
    def prepare_request_headers(headers: Dict, account_id: str, region_name: str):
        """
        Modify the Credentials field of Authorization header to achieve namespacing in DynamoDBLocal.
        """
        region_name = DynamoDBProvider.ddb_region_name(region_name)
        key = get_ddb_access_key(account_id, region_name)

        # DynamoDBLocal namespaces based on the value of Credentials
        # Since we want to namespace by both account ID and region, use an aggregate key
        # We also replace the region to keep compatibility with NoSQL Workbench
        headers["Authorization"] = re.sub(
            AUTH_CREDENTIAL_REGEX,
            rf"Credential={key}/\2/{region_name}/\4/",
            headers.get("Authorization") or "",
            flags=re.IGNORECASE,
        )

    def fix_consumed_capacity(self, request: Dict, result: Dict):
        # make sure we append 'ConsumedCapacity', which is properly
        # returned by dynalite, but not by AWS's DynamoDBLocal
        table_name = request.get("TableName")
        return_cap = request.get("ReturnConsumedCapacity")
        if "ConsumedCapacity" not in result and return_cap in ["TOTAL", "INDEXES"]:
            request["ConsumedCapacity"] = {
                "TableName": table_name,
                "CapacityUnits": 5,  # TODO hardcoded
                "ReadCapacityUnits": 2,
                "WriteCapacityUnits": 3,
            }

    def fix_table_arn(self, account_id: str, region_name: str, arn: str) -> str:
        """
        Set the correct account ID and region in ARNs returned by DynamoDB Local.
        """
        partition = get_partition(region_name)
        return (
            arn.replace("arn:aws:", f"arn:{partition}:")
            .replace(":ddblocal:", f":{region_name}:")
            .replace(":000000000000:", f":{account_id}:")
        )

    def batch_execute_statement(
        self,
        context: RequestContext,
        statements: PartiQLBatchRequest,
        return_consumed_capacity: ReturnConsumedCapacity = None,
        **kwargs,
    ) -> BatchExecuteStatementOutput:
        result = self.forward_request(context)
        return result

    @staticmethod
    def get_record_template(region_name: str, stream_view_type: str | None = None) -> StreamRecord:
        record = {
            "eventID": short_uid(),
            "eventVersion": "1.1",
            "dynamodb": {
                # expects nearest second rounded down
                "ApproximateCreationDateTime": int(time.time()),
                "SizeBytes": -1,
            },
            "awsRegion": region_name,
            "eventSource": "aws:dynamodb",
        }
        if stream_view_type:
            record["dynamodb"]["StreamViewType"] = stream_view_type

        return record

    def check_provisioned_throughput(self, action):
        """
        Check rate limiting for an API operation and raise an error if provisioned throughput is exceeded.
        """
        if self.should_throttle(action):
            message = (
                "The level of configured provisioned throughput for the table was exceeded. "
                + "Consider increasing your provisioning level with the UpdateTable API"
            )
            raise ProvisionedThroughputExceededException(message)

    def action_should_throttle(self, action, actions):
        throttled = [f"{ACTION_PREFIX}{a}" for a in actions]
        return (action in throttled) or (action in actions)

    def should_throttle(self, action):
        if (
            not config.DYNAMODB_READ_ERROR_PROBABILITY
            and not config.DYNAMODB_ERROR_PROBABILITY
            and not config.DYNAMODB_WRITE_ERROR_PROBABILITY
        ):
            # early exit so we don't need to call random()
            return False

        rand = random.random()
        if rand < config.DYNAMODB_READ_ERROR_PROBABILITY and self.action_should_throttle(
            action, READ_THROTTLED_ACTIONS
        ):
            return True
        elif rand < config.DYNAMODB_WRITE_ERROR_PROBABILITY and self.action_should_throttle(
            action, WRITE_THROTTLED_ACTIONS
        ):
            return True
        elif rand < config.DYNAMODB_ERROR_PROBABILITY and self.action_should_throttle(
            action, THROTTLED_ACTIONS
        ):
            return True
        return False


# ---
# Misc. util functions
# ---


def get_global_secondary_index(account_id: str, region_name: str, table_name: str, index_name: str):
    schema = SchemaExtractor.get_table_schema(table_name, account_id, region_name)
    for index in schema["Table"].get("GlobalSecondaryIndexes", []):
        if index["IndexName"] == index_name:
            return index
    raise ResourceNotFoundException("Index not found")


def is_local_secondary_index(
    account_id: str, region_name: str, table_name: str, index_name: str
) -> bool:
    schema = SchemaExtractor.get_table_schema(table_name, account_id, region_name)
    for index in schema["Table"].get("LocalSecondaryIndexes", []):
        if index["IndexName"] == index_name:
            return True
    return False


def is_index_query_valid(account_id: str, region_name: str, query_data: dict) -> bool:
    table_name = to_str(query_data["TableName"])
    index_name = to_str(query_data["IndexName"])
    if is_local_secondary_index(account_id, region_name, table_name, index_name):
        return True
    index_query_type = query_data.get("Select")
    index = get_global_secondary_index(account_id, region_name, table_name, index_name)
    index_projection_type = index.get("Projection").get("ProjectionType")
    if index_query_type == "ALL_ATTRIBUTES" and index_projection_type != "ALL":
        return False
    return True


def kinesis_stream_exists(stream_arn):
    account_id = extract_account_id_from_arn(stream_arn)
    region_name = extract_region_from_arn(stream_arn)

    kinesis = connect_to(
        aws_access_key_id=account_id,
        aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
        region_name=region_name,
    ).kinesis
    stream_name_from_arn = stream_arn.split("/", 1)[1]
    # check if the stream exists in kinesis for the user
    filtered = list(
        filter(
            lambda stream_name: stream_name == stream_name_from_arn,
            kinesis.list_streams()["StreamNames"],
        )
    )
    return bool(filtered)
