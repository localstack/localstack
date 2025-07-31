import json

from localstack.services.apigateway.models import ApiGatewayStore
from localstack.services.cloudformation.stores import CloudFormationStore
from localstack.services.cloudwatch.models import CloudWatchStore
from localstack.services.dynamodb.models import DynamoDBStore
from localstack.services.dynamodbstreams.models import DynamoDbStreamsStore
from localstack.services.events.v1.models import EventsStore
from localstack.services.firehose.models import FirehoseStore
from localstack.services.kinesis.models import KinesisStore
from localstack.services.kms.models import KmsStore
from localstack.services.lambda_.invocation.models import LambdaStore
from localstack.services.logs.models import LogsStore
from localstack.services.opensearch.models import OpenSearchStore
from localstack.services.route53.models import Route53Store
from localstack.services.route53resolver.models import Route53ResolverStore
from localstack.services.s3.models import S3Store
from localstack.services.sns.models import SnsStore
from localstack.services.sqs.models import SqsStore
from localstack.services.stepfunctions.backend.store import SFNStore
from localstack.services.stores import BaseStore, CrossRegionAttribute
from localstack.services.sts.models import STSStore
from localstack.services.transcribe.models import TranscribeStore
from localstack.state.schema import StoreSchemaBuilder, get_fully_qualified_name


def test_smoke_schema_dumps():
    """
    This test extracts the schema for all the stores in the repo and dumps it.
    It's just a smoke test to make sure
    """
    stores = [
        ApiGatewayStore,
        CloudFormationStore,
        CloudWatchStore,
        DynamoDBStore,
        DynamoDbStreamsStore,
        EventsStore,
        FirehoseStore,
        KinesisStore,
        KmsStore,
        LambdaStore,
        LogsStore,
        OpenSearchStore,
        Route53Store,
        Route53ResolverStore,
        S3Store,
        SnsStore,
        SqsStore,
        SFNStore,
        STSStore,
        TranscribeStore,
    ]
    for store in stores:
        build = StoreSchemaBuilder(store)
        schema = build.build_schema()
        assert schema["type"] == get_fully_qualified_name(store)
        assert schema["attributes"], "A schema is missing attributes to be extracted"
        # Just making sure the returned schema can be serialized to JSON
        assert json.dumps(schema)


def test_simple_store():
    class MyStore(BaseStore):
        field1: dict[str, str] = CrossRegionAttribute(default=dict)
        field2: list[str] = CrossRegionAttribute(default=list)
        field3: str | int = CrossRegionAttribute(default=str)
        field4: tuple[str, int] = CrossRegionAttribute(default=tuple)

    build = StoreSchemaBuilder(MyStore)
    schema = build.build_schema()
    print(json.dumps(schema, indent=2))
