import logging
import re
from binascii import crc32
from typing import Dict, List, Optional

from cachetools import TTLCache
from moto.core.exceptions import JsonRESTError

from localstack.utils.aws import aws_stack
from localstack.utils.json import canonical_json
from localstack.utils.strings import to_bytes
from localstack.utils.testutil import list_all_resources

LOG = logging.getLogger(__name__)

# cache schema definitions
SCHEMA_CACHE = TTLCache(maxsize=50, ttl=20)


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
    def extract_keys(cls, item: Dict, table_name: str) -> Optional[Dict]:
        key_schema = cls.get_key_schema(table_name)
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
    def get_key_schema(cls, table_name: str) -> Optional[List[Dict]]:
        from localstack.services.dynamodb.provider import DynamoDBRegion

        table_definitions = DynamoDBRegion.get().table_definitions
        table_def = table_definitions.get(table_name)
        if not table_def:
            raise Exception(f"Unknown table: {table_name} not found in {table_definitions.keys()}")
        return table_def["KeySchema"]

    @classmethod
    def get_table_schema(cls, table_name):
        key = f"{aws_stack.get_region()}/{table_name}"
        schema = SCHEMA_CACHE.get(key)
        if not schema:
            ddb_client = aws_stack.connect_to_service("dynamodb")
            schema = ddb_client.describe_table(TableName=table_name)
            SCHEMA_CACHE[key] = schema
        return schema


class ItemFinder:
    @staticmethod
    def find_existing_item(put_item: Dict, table_name=None) -> Optional[Dict]:
        table_name = table_name or put_item["TableName"]
        ddb_client = aws_stack.connect_to_service("dynamodb")

        search_key = {}
        if "Key" in put_item:
            search_key = put_item["Key"]
        else:
            schema = SchemaExtractor.get_table_schema(table_name)
            schemas = [schema["Table"]["KeySchema"]]
            for index in schema["Table"].get("GlobalSecondaryIndexes", []):
                # TODO
                # schemas.append(index['KeySchema'])
                pass
            for schema in schemas:
                for key in schema:
                    key_name = key["AttributeName"]
                    search_key[key_name] = put_item["Item"][key_name]
            if not search_key:
                return

        req = {"TableName": table_name, "Key": search_key}
        existing_item = aws_stack.dynamodb_get_item_raw(req)
        if not existing_item:
            return existing_item
        if "Item" not in existing_item:
            if "message" in existing_item:
                table_names = ddb_client.list_tables()["TableNames"]
                msg = (
                    "Unable to get item from DynamoDB (existing tables: %s ...truncated if >100 tables): %s"
                    % (
                        table_names,
                        existing_item["message"],
                    )
                )
                LOG.warning(msg)
            return
        return existing_item.get("Item")

    @classmethod
    def list_existing_items_for_statement(cls, partiql_statement: str) -> List:
        table_name = extract_table_name_from_partiql_update(partiql_statement)
        if not table_name:
            return []
        all_items = cls.get_all_table_items(table_name)
        return all_items

    @staticmethod
    def get_all_table_items(table_name: str) -> List:
        ddb_client = aws_stack.connect_to_service("dynamodb")
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


def calculate_crc32(response):
    return crc32(to_bytes(response.content)) & 0xFFFFFFFF
