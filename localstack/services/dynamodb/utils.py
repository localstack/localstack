import logging
import re
from typing import Dict, List, Optional

from cachetools import TTLCache
from moto.core.exceptions import JsonRESTError

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.dynamodb import ResourceNotFoundException
from localstack.constants import TEST_AWS_SECRET_ACCESS_KEY
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import dynamodb_table_arn
from localstack.utils.json import canonical_json
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
    def extract_keys(
        cls, item: Dict, table_name: str, account_id: str = None, region_name: str = None
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
        cls, table_name: str, account_id: str = None, region_name: str = None
    ) -> Optional[List[Dict]]:
        from localstack.services.dynamodb.provider import get_store

        account_id = account_id or get_aws_account_id()
        region_name = region_name or aws_stack.get_region()

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
    def get_table_schema(cls, table_name: str, account_id: str = None, region_name: str = None):
        account_id = account_id or get_aws_account_id()
        region_name = region_name or aws_stack.get_region()
        key = dynamodb_table_arn(
            table_name=table_name, account_id=account_id, region_name=region_name
        )
        schema = SCHEMA_CACHE.get(key)
        if not schema:
            # TODO: consider making in-memory lookup instead of API call
            ddb_client = aws_stack.connect_to_service(
                "dynamodb",
                aws_access_key_id=account_id,
                aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
                region_name=region_name,
            )
            try:
                schema = ddb_client.describe_table(TableName=table_name)
                SCHEMA_CACHE[key] = schema
            except Exception as e:
                if "ResourceNotFoundException" in str(e):
                    raise ResourceNotFoundException(f"Unknown table: {table_name}") from e
                raise
        return schema


class ItemFinder:
    @staticmethod
    def find_existing_item(
        put_item: Dict, table_name: str = None, account_id: str = None, region_name: str = None
    ) -> Optional[Dict]:
        from localstack.services.dynamodb.provider import ValidationException

        table_name = table_name or put_item["TableName"]
        ddb_client = aws_stack.connect_to_service(
            "dynamodb",
            aws_access_key_id=account_id or get_aws_account_id(),
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name or aws_stack.get_region(),
        )

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
                    key_value = put_item["Item"].get(key_name)
                    if not key_value:
                        raise ValidationException(
                            "The provided key element does not match the schema"
                        )
                    search_key[key_name] = key_value
            if not search_key:
                return

        req = {"TableName": table_name, "Key": search_key}
        existing_item = ddb_client.get_item(**req)
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
        ddb_client = aws_stack.connect_to_service(
            "dynamodb",
            aws_access_key_id=get_aws_account_id(),
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=aws_stack.get_region(),
        )
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
