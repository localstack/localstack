import logging
import re
from binascii import crc32
from typing import Dict, List, Optional

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from cachetools import TTLCache
from moto.core.exceptions import JsonRESTError

from localstack.aws.api import RequestContext
from localstack.aws.api.dynamodb import (
    AttributeMap,
    BatchGetRequestMap,
    BatchGetResponseMap,
    Delete,
    DeleteRequest,
    Put,
    PutRequest,
    ResourceNotFoundException,
    TableName,
    Update,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.http import Response
from localstack.utils.aws.arns import dynamodb_table_arn, get_partition
from localstack.utils.json import canonical_json
from localstack.utils.testutil import list_all_resources

LOG = logging.getLogger(__name__)

# cache schema definitions
SCHEMA_CACHE = TTLCache(maxsize=50, ttl=20)

_ddb_local_arn_pattern = re.compile(
    r'("TableArn"|"LatestStreamArn"|"StreamArn"|"ShardIterator"|"IndexArn")\s*:\s*"arn:[a-z-]+:dynamodb:ddblocal:000000000000:([^"]+)"'
)
_ddb_local_region_pattern = re.compile(r'"awsRegion"\s*:\s*"([^"]+)"')
_ddb_local_exception_arn_pattern = re.compile(r'arn:[a-z-]+:dynamodb:ddblocal:000000000000:([^"]+)')


def get_ddb_access_key(account_id: str, region_name: str) -> str:
    """
    Get the access key to be used while communicating with DynamoDB Local.

    DDBLocal supports namespacing as an undocumented feature. It works based on the value of the `Credentials`
    field of the `Authorization` header. We use a concatenated value of account ID and region to achieve
    namespacing.
    """
    return f"{account_id}{region_name}".replace("-", "")


class ItemSet:
    """Represents a set of items and provides utils to find individual items in the set"""

    def __init__(self, items: List[Dict], key_schema: List[Dict]):
        self.items_list = items
        self.key_schema = key_schema
        self._build_dict()

    def _build_dict(self):
        self.items_dict = {}
        for item in self.items_list:
            self.items_dict[self._hashable_key(item)] = item

    def _hashable_key(self, item: Dict):
        keys = SchemaExtractor.extract_keys_for_schema(item=item, key_schema=self.key_schema)
        return canonical_json(keys)

    def find_item(self, item: Dict) -> Optional[Dict]:
        key = self._hashable_key(item)
        return self.items_dict.get(key)


class SchemaExtractor:
    @classmethod
    def extract_keys(
        cls, item: Dict, table_name: str, account_id: str, region_name: str
    ) -> Optional[Dict]:
        key_schema = cls.get_key_schema(table_name, account_id, region_name)
        return cls.extract_keys_for_schema(item, key_schema)

    @classmethod
    def extract_keys_for_schema(cls, item: Dict, key_schema: List[Dict]):
        result = {}
        for key in key_schema:
            attr_name = key["AttributeName"]
            if attr_name not in item:
                raise JsonRESTError(
                    error_type="ValidationException",
                    message="One of the required keys was not given a value",
                )
            result[attr_name] = item[attr_name]
        return result

    @classmethod
    def get_key_schema(
        cls, table_name: str, account_id: str, region_name: str
    ) -> Optional[List[Dict]]:
        from localstack.services.dynamodb.provider import get_store

        table_definitions: Dict = get_store(
            account_id=account_id,
            region_name=region_name,
        ).table_definitions
        table_def = table_definitions.get(table_name)
        if not table_def:
            # Try fetching from the backend in case table_definitions has been reset
            schema = cls.get_table_schema(
                table_name=table_name, account_id=account_id, region_name=region_name
            )
            if not schema:
                raise ResourceNotFoundException(f"Unknown table: {table_name} not found")
            # Save the schema in the cache
            table_definitions[table_name] = schema["Table"]
            table_def = table_definitions[table_name]
        return table_def["KeySchema"]

    @classmethod
    def get_table_schema(cls, table_name: str, account_id: str, region_name: str):
        key = dynamodb_table_arn(
            table_name=table_name, account_id=account_id, region_name=region_name
        )
        schema = SCHEMA_CACHE.get(key)
        if not schema:
            # TODO: consider making in-memory lookup instead of API call
            ddb_client = connect_to(
                aws_access_key_id=account_id,
                aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                region_name=region_name,
            ).dynamodb
            try:
                schema = ddb_client.describe_table(TableName=table_name)
                SCHEMA_CACHE[key] = schema
            except Exception as e:
                if "ResourceNotFoundException" in str(e):
                    raise ResourceNotFoundException(f"Unknown table: {table_name}") from e
                raise
        return schema

    @classmethod
    def invalidate_table_schema(cls, table_name: str, account_id: str, region_name: str):
        """
        Allow cached table schemas to be invalidated without waiting for the TTL to expire
        """
        key = dynamodb_table_arn(
            table_name=table_name, account_id=account_id, region_name=region_name
        )
        SCHEMA_CACHE.pop(key, None)


class ItemFinder:
    @staticmethod
    def get_ddb_local_client(account_id: str, region_name: str, endpoint_url: str):
        ddb_client = connect_to(
            aws_access_key_id=get_ddb_access_key(account_id, region_name),
            region_name=region_name,
            endpoint_url=endpoint_url,
        ).dynamodb
        return ddb_client

    @staticmethod
    def find_existing_item(
        put_item: Dict,
        table_name: str,
        account_id: str,
        region_name: str,
        endpoint_url: str,
    ) -> Optional[AttributeMap]:
        from localstack.services.dynamodb.provider import ValidationException

        ddb_client = ItemFinder.get_ddb_local_client(account_id, region_name, endpoint_url)

        search_key = {}
        if "Key" in put_item:
            search_key = put_item["Key"]
        else:
            schema = SchemaExtractor.get_table_schema(table_name, account_id, region_name)
            schemas = [schema["Table"]["KeySchema"]]
            for index in schema["Table"].get("GlobalSecondaryIndexes", []):
                # TODO
                # schemas.append(index['KeySchema'])
                pass
            for schema in schemas:
                for key in schema:
                    key_name = key["AttributeName"]
                    key_value = put_item["Item"].get(key_name)
                    if not key_value:
                        raise ValidationException(
                            "The provided key element does not match the schema"
                        )
                    search_key[key_name] = key_value
            if not search_key:
                return

        try:
            existing_item = ddb_client.get_item(TableName=table_name, Key=search_key)
        except ddb_client.exceptions.ClientError as e:
            LOG.warning(
                "Unable to get item from DynamoDB table '%s': %s",
                table_name,
                e,
            )
            return

        return existing_item.get("Item")

    @staticmethod
    def find_existing_items(
        put_items_per_table: dict[
            TableName, list[PutRequest | DeleteRequest | Put | Update | Delete]
        ],
        account_id: str,
        region_name: str,
        endpoint_url: str,
    ) -> BatchGetResponseMap:
        from localstack.services.dynamodb.provider import ValidationException

        ddb_client = ItemFinder.get_ddb_local_client(account_id, region_name, endpoint_url)

        get_items_request: BatchGetRequestMap = {}
        for table_name, put_item_reqs in put_items_per_table.items():
            table_schema = None
            for put_item in put_item_reqs:
                search_key = {}
                if "Key" in put_item:
                    search_key = put_item["Key"]
                else:
                    if not table_schema:
                        table_schema = SchemaExtractor.get_table_schema(
                            table_name, account_id, region_name
                        )

                    schemas = [table_schema["Table"]["KeySchema"]]
                    for index in table_schema["Table"].get("GlobalSecondaryIndexes", []):
                        # TODO
                        # schemas.append(index['KeySchema'])
                        pass
                    for schema in schemas:
                        for key in schema:
                            key_name = key["AttributeName"]
                            key_value = put_item["Item"].get(key_name)
                            if not key_value:
                                raise ValidationException(
                                    "The provided key element does not match the schema"
                                )
                            search_key[key_name] = key_value
                    if not search_key:
                        continue
                table_keys = get_items_request.setdefault(table_name, {"Keys": []})
                table_keys["Keys"].append(search_key)

        try:
            existing_items = ddb_client.batch_get_item(RequestItems=get_items_request)
        except ddb_client.exceptions.ClientError as e:
            LOG.warning(
                "Unable to get items from DynamoDB tables '%s': %s",
                list(put_items_per_table.values()),
                e,
            )
            return {}

        return existing_items.get("Responses", {})

    @classmethod
    def list_existing_items_for_statement(
        cls, partiql_statement: str, account_id: str, region_name: str, endpoint_url: str
    ) -> List:
        table_name = extract_table_name_from_partiql_update(partiql_statement)
        if not table_name:
            return []
        all_items = cls.get_all_table_items(
            account_id=account_id,
            region_name=region_name,
            table_name=table_name,
            endpoint_url=endpoint_url,
        )
        return all_items

    @staticmethod
    def get_all_table_items(
        account_id: str, region_name: str, table_name: str, endpoint_url: str
    ) -> List:
        ddb_client = ItemFinder.get_ddb_local_client(account_id, region_name, endpoint_url)
        dynamodb_kwargs = {"TableName": table_name}
        all_items = list_all_resources(
            lambda kwargs: ddb_client.scan(**{**kwargs, **dynamodb_kwargs}),
            last_token_attr_name="LastEvaluatedKey",
            next_token_attr_name="ExclusiveStartKey",
            list_attr_name="Items",
        )
        return all_items


def extract_table_name_from_partiql_update(statement: str) -> Optional[str]:
    regex = r"^\s*(UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+([^\s]+).*"
    match = re.match(regex, statement, flags=re.IGNORECASE | re.MULTILINE)
    return match and match.group(2)


def dynamize_value(value) -> dict:
    """
    Take a scalar Python value or dict/list and return a dict consisting of the Amazon DynamoDB type specification and
    the value that needs to be sent to Amazon DynamoDB.  If the type of the value is not supported, raise a TypeError
    """
    return TypeSerializer().serialize(value)


def de_dynamize_record(item: dict) -> dict:
    """
    Return the given item in DynamoDB format parsed as regular dict object, i.e., convert
    something like `{'foo': {'S': 'test'}, 'bar': {'N': 123}}` to `{'foo': 'test', 'bar': 123}`.
    Note: This is the reverse operation of `dynamize_value(...)` above.
    """
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(v) for k, v in item.items()}


def modify_ddblocal_arns(chain, context: RequestContext, response: Response):
    """A service response handler that modifies the dynamodb backend response."""
    if response_content := response.get_data(as_text=True):
        partition = get_partition(context.region)

        def _convert_arn(matchobj):
            key = matchobj.group(1)
            table_name = matchobj.group(2)
            return f'{key}: "arn:{partition}:dynamodb:{context.region}:{context.account_id}:{table_name}"'

        # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
        content_replaced = _ddb_local_arn_pattern.sub(
            _convert_arn,
            response_content,
        )
        if context.service.service_name == "dynamodbstreams":
            content_replaced = _ddb_local_region_pattern.sub(
                f'"awsRegion": "{context.region}"', content_replaced
            )
            if context.service_exception:
                content_replaced = _ddb_local_exception_arn_pattern.sub(
                    rf"arn:{partition}:dynamodb:{context.region}:{context.account_id}:\g<1>",
                    content_replaced,
                )

        if content_replaced != response_content:
            response.data = content_replaced
            # make sure the service response is parsed again later
            context.service_response = None

    # update x-amz-crc32 header required by some clients
    response.headers["x-amz-crc32"] = crc32(response.data) & 0xFFFFFFFF
