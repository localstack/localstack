import json
import os
from operator import itemgetter

import aws_cdk as cdk
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as awslambda
import aws_cdk.aws_opensearchservice as opensearch
import pytest
from aws_cdk.aws_lambda_event_sources import DynamoEventSource
from botocore.exceptions import ClientError
from constructs import Construct
from localstack_snapshot.snapshots.transformer import GenericTransformer, KeyValueBasedTransformer

from localstack.testing.pytest import markers
from localstack.testing.scenario.cdk_lambda_helper import load_python_lambda_to_s3
from localstack.testing.scenario.provisioning import InfraProvisioner, cleanup_s3_bucket
from localstack.utils.aws.resources import create_s3_bucket
from localstack.utils.files import load_file
from localstack.utils.strings import to_bytes
from localstack.utils.sync import retry

"""

This scenario is based on https://github.com/aws-samples/aws-bookstore-demo-app

Currently includes:
- DynamoDB
- OpenSearch
- EventSourceMapping
- several Lambdas for pre-filling + querying dynamodb + opensearch

Scenarios:
* First tests calls a Lambda that pre-fills the dynamoDB
   * EventSourceMapping: will retrieve stream from DynamoDB and send PUT requests to opensearch cluster
* get/list Lambdas that query dynamodb
* search Lambda that sends query to opensearch (for category, name, title of books)
"""

S3_BUCKET_BOOKS_INIT = "book-init-data-store-scenario-test"
S3_KEY_BOOKS_INIT = "books.json"
SEARCH_KEY = "search.zip"
SEARCH_UPDATE_KEY = "search_update.zip"


@markers.acceptance_test
class TestBookstoreApplication:
    @pytest.fixture(scope="class")
    def patch_opensearch_strategy(self):
        """patching the endpoint strategy for opensearch to path, to make the endpoint resolution in the lambda easier"""
        from _pytest.monkeypatch import MonkeyPatch

        from localstack import config

        mpatch = MonkeyPatch()
        mpatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")
        yield mpatch
        mpatch.undo()

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup, patch_opensearch_strategy):
        infra = infrastructure_setup("Bookstore")

        search_book_fn_path = os.path.join(os.path.dirname(__file__), "functions/search.py")
        search_update_fn_path = os.path.join(
            os.path.dirname(__file__), "functions/update_search_cluster.py"
        )
        # custom provisioning
        additional_packages = ["requests", "requests-aws4auth", "urllib3==1.26.6"]
        asset_bucket = infra.get_asset_bucket()
        infra.add_custom_setup_provisioning_step(
            lambda: load_python_lambda_to_s3(
                aws_client.s3,
                bucket_name=asset_bucket,
                key_name=SEARCH_KEY,
                code_path=search_book_fn_path,
                additional_python_packages=additional_packages,
            )
        )
        infra.add_custom_setup_provisioning_step(
            lambda: load_python_lambda_to_s3(
                aws_client.s3,
                bucket_name=asset_bucket,
                key_name=SEARCH_UPDATE_KEY,
                code_path=search_update_fn_path,
                additional_python_packages=additional_packages,
            )
        )

        # CDK-based provisioning
        stack = cdk.Stack(infra.cdk_app, "BookstoreStack")
        books_api = BooksApi(
            stack,
            "BooksApi",
            search_key=SEARCH_KEY,
            search_update_key=SEARCH_UPDATE_KEY,
        )

        cdk.CfnOutput(stack, "BooksTableName", value=books_api.books_table.table_name)
        cdk.CfnOutput(stack, "SearchDomain", value=books_api.opensearch_domain.domain_endpoint)
        cdk.CfnOutput(stack, "SearchDomainName", value=books_api.opensearch_domain.domain_name)
        cdk.CfnOutput(stack, "GetBooksFn", value=books_api.get_book_fn.function_name)
        cdk.CfnOutput(stack, "ListBooksFn", value=books_api.list_books_fn.function_name)
        cdk.CfnOutput(stack, "InitBooksTableFn", value=books_api.load_books_helper_fn.function_name)
        cdk.CfnOutput(stack, "SearchForBooksFn", value=books_api.search_book_fn.function_name)

        # set skip_teardown=True to prevent the stack to be deleted
        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    def test_setup(self, aws_client, infrastructure, snapshot, cleanups):
        outputs = infrastructure.get_stack_outputs("BookstoreStack")
        load_books_helper_fn = outputs.get("InitBooksTableFn")

        # pre-fill dynamodb
        # json-data is from https://aws-bookstore-demo.s3.amazonaws.com/data/books.json
        try:
            create_s3_bucket(bucket_name=S3_BUCKET_BOOKS_INIT, s3_client=aws_client.s3)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
                raise exc
        cleanups.append(
            lambda: cleanup_s3_bucket(
                aws_client.s3, bucket_name=S3_BUCKET_BOOKS_INIT, delete_bucket=True
            )
        )

        file_name = os.path.join(os.path.dirname(__file__), "./resources/initial_books.json")
        aws_client.s3.upload_file(
            Filename=file_name,
            Bucket=S3_BUCKET_BOOKS_INIT,
            Key=S3_KEY_BOOKS_INIT,
        )

        aws_client.lambda_.invoke(FunctionName=load_books_helper_fn)

        # after invoking the dynamodb should be filled
        table_name = outputs.get("BooksTableName")

        # wait until everything is filled, we should get 56 items in the table
        def _verify_dynamodb_count():
            res = aws_client.dynamodb.scan(TableName=table_name, Select="COUNT")
            assert res["Count"] == 56

        retry(_verify_dynamodb_count, retries=20, sleep=1)

        item_count = aws_client.dynamodb.scan(TableName=table_name, Select="COUNT")
        snapshot.match("scan_count", item_count)

        # chose one id from the initial_books.json
        result = aws_client.dynamodb.get_item(
            TableName=table_name, Key={"id": {"S": "nuklcm5b-d93b-11e8-9f8b-f2801f1b9fd1"}}
        )
        snapshot.match("get-item", result)

    @markers.aws.validated
    def test_lambda_dynamodb(self, aws_client, infrastructure, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        def _convert_payload_body_to_json(snapshot_content: dict, *args) -> dict:
            """converts the "body" payload into a comparable json"""
            for k, v in snapshot_content.items():
                if isinstance(v, dict) and "Payload" in v:
                    v = v["Payload"]
                if isinstance(v, dict) and "body" in v:
                    v["body"] = json.loads(v["body"])
                    if isinstance(v["body"], list):
                        v["body"].sort(key=itemgetter("id"))
            return snapshot_content

        snapshot.add_transformer(GenericTransformer(_convert_payload_body_to_json))

        outputs = infrastructure.get_stack_outputs("BookstoreStack")
        get_books_fn = outputs.get("GetBooksFn")
        list_books_fn = outputs.get("ListBooksFn")

        result = aws_client.lambda_.invoke(
            FunctionName=get_books_fn,
            Payload=to_bytes(
                json.dumps({"pathParameters": {"id": "0vld6p1u-d93b-11e8-9f8b-f2801f1b9fd1"}})
            ),
        )
        snapshot.match("get_books_fn", result)
        payload_category = {"queryStringParameters": {"category": "Woodwork"}}

        result = aws_client.lambda_.invoke(
            FunctionName=list_books_fn,
            Payload=to_bytes(json.dumps(payload_category)),
        )
        result = json.load(result["Payload"])
        snapshot.match("list_books_cat_woodwork", result)

        # test another category
        payload_category["queryStringParameters"]["category"] = "Home Improvement"
        result = aws_client.lambda_.invoke(
            FunctionName=list_books_fn,
            Payload=to_bytes(json.dumps(payload_category)),
        )
        result = json.load(result["Payload"])
        snapshot.match("list_books_cat_home", result)

        # without category it should return all books
        result = aws_client.lambda_.invoke(FunctionName=list_books_fn)
        result = json.load(result["Payload"])
        assert len(json.loads(result["body"])) == 56

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$.._shards.successful", "$.._shards.total"])
    def test_search_books(self, aws_client, infrastructure, snapshot):
        def _sort_hits(snapshot_content: dict, *args) -> dict:
            """sort "hits" list by id"""
            for k, v in snapshot_content.items():
                if "hits" in v and "hits" in v["hits"]:
                    v["hits"]["hits"].sort(key=itemgetter("_id"))
            return snapshot_content

        snapshot.add_transformer(GenericTransformer(_sort_hits))
        snapshot.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: v
                if k in ("took", "max_score", "_score")
                and (isinstance(v, float) or isinstance(v, int))
                else None,
                replacement="<amount>",
                replace_reference=False,
            )
        )
        outputs = infrastructure.get_stack_outputs("BookstoreStack")
        search_fn = outputs.get("SearchForBooksFn")

        def _verify_search(category: str, expected_amount: int):
            res = aws_client.lambda_.invoke(
                FunctionName=search_fn,
                Payload=to_bytes(json.dumps({"queryStringParameters": {"q": category}})),
            )
            res = json.load(res["Payload"])
            search_res = json.loads(res["body"])["hits"]["total"]["value"]
            # compare total hits with expected results, total hits are not bound by the size limit of the query
            assert search_res == expected_amount
            return res

        # it might take a little until the search is fully functional
        # because we have an event source mapping
        retry(lambda: _verify_search("cookbooks", 26), retries=100, sleep=1)

        # search for book with title "Spaghetti"
        search_payload = {"queryStringParameters": {"q": "Spaghetti"}}

        result = aws_client.lambda_.invoke(
            FunctionName=search_fn,
            Payload=to_bytes(json.dumps(search_payload)),
        )
        result = json.load(result["Payload"])
        search_result = json.loads(result["body"])
        snapshot.match("search_name_spaghetti", search_result)

        # we witnessed a flaky test in CI where some search queries did not return the expected result
        # assuming some entries might need longer to be indexed
        # search for author
        result = retry(lambda: _verify_search("aubree", 5), retries=20, sleep=1)
        search_result = json.loads(result["body"])
        snapshot.match("search_author_aubree", search_result)

        # search for category
        result = retry(lambda: _verify_search("Home Impro", 5), retries=20, sleep=1)
        search_result = json.loads(result["body"])
        snapshot.match("search_cat_home_impro", search_result)

        # search for a non-existent string (should return 0 results)
        search_payload["queryStringParameters"]["q"] = "Something"
        result = aws_client.lambda_.invoke(
            FunctionName=search_fn,
            Payload=to_bytes(json.dumps(search_payload)),
        )
        result = json.load(result["Payload"])
        search_result = json.loads(result["body"])
        snapshot.match("search_no_result", search_result)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..ClusterConfig.DedicatedMasterCount",  # added in LS
            "$..ClusterConfig.DedicatedMasterEnabled",  # added in LS
            "$..ClusterConfig.DedicatedMasterType",  # added in LS
            "$..ClusterConfig.Options.DedicatedMasterCount",  # added in LS
            "$..ClusterConfig.Options.DedicatedMasterType",  # added in LS
            "$..DomainStatusList..EBSOptions.Iops",  # added in LS
            "$..DomainStatusList..IPAddressType",  # missing
            "$..DomainStatusList..DomainProcessingStatus",  # missing
            "$..DomainStatusList..ModifyingProperties",  # missing
            "$..SoftwareUpdateOptions",  # missing
            "$..OffPeakWindowOptions",  # missing
            "$..ChangeProgressDetails",  # missing
            "$..AutoTuneOptions.UseOffPeakWindow",  # missing
            "$..AutoTuneOptions.Options.UseOffPeakWindow",  # missing
            "$..ClusterConfig.MultiAZWithStandbyEnabled",  # missing
            "$..AdvancedSecurityOptions.AnonymousAuthEnabled",  # missing
            "$..AdvancedSecurityOptions.Options.AnonymousAuthEnabled",  # missing
            "$..DomainConfig.ClusterConfig.Options.WarmEnabled",  # missing
            "$..DomainConfig.IPAddressType",  # missing
            "$..DomainConfig.ModifyingProperties",  # missing
            "$..ClusterConfig.Options.ColdStorageOptions",  # missing
            "$..ClusterConfig.Options.MultiAZWithStandbyEnabled",  # missing
            # TODO different values:
            "$..Processing",
            "$..ServiceSoftwareOptions.CurrentVersion",
            "$..ClusterConfig.DedicatedMasterEnabled",
            "$..ClusterConfig.InstanceType",
            "$..SnapshotOptions.Options.AutomatedSnapshotStartHour",
            "$..ClusterConfig.Options.DedicatedMasterEnabled",
            "$..ClusterConfig.Options.InstanceType",
            "$..AutoTuneOptions.State",
            "$..EBSOptions.Options.VolumeSize",
            '$..AdvancedOptions."rest.action.multi.allow_explicit_index"',
            '$..AdvancedOptions.Options."rest.action.multi.allow_explicit_index"',
            # TODO currently no support for ElasticSearch 2.3 + 1.5
            "$..Versions",
        ]
    )
    def test_opensearch_crud(self, aws_client, infrastructure, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("DomainId"))
        snapshot.add_transformer(snapshot.transform.key_value("DomainName"))
        snapshot.add_transformer(snapshot.transform.key_value("ChangeId"))
        snapshot.add_transformer(snapshot.transform.key_value("Endpoint"), priority=-1)
        # UpdateVersion seems to change with almost every execution
        snapshot.add_transformer(
            snapshot.transform.key_value("UpdateVersion", reference_replacement=False)
        )
        outputs = infrastructure.get_stack_outputs("BookstoreStack")
        opensearch_domain_name = outputs.get("SearchDomainName")

        describe_domains = aws_client.opensearch.describe_domains(
            DomainNames=[opensearch_domain_name]
        )
        snapshot.match("describe_domains", describe_domains)
        arn = describe_domains["DomainStatusList"][0]["ARN"]
        domain_names = aws_client.opensearch.list_domain_names()

        snapshot.match("list_domain_names", domain_names)

        domain_config = aws_client.opensearch.describe_domain_config(
            DomainName=opensearch_domain_name
        )
        snapshot.match("describe_domain_config", domain_config)

        # add tags
        aws_client.opensearch.add_tags(
            ARN=arn,
            TagList=[
                {"Key": "scenario/test", "Value": "bookstore"},
                {"Key": "bookstore", "Value": "search"},
            ],
        )
        # list tags
        tags = aws_client.opensearch.list_tags(ARN=arn)
        tags["TagList"].sort(key=itemgetter("Key"))
        snapshot.match("list_tags", tags)
        # remove tags
        aws_client.opensearch.remove_tags(ARN=arn, TagKeys=["bookstore"])
        tags = aws_client.opensearch.list_tags(ARN=arn)
        tags["TagList"].sort(key=itemgetter("Key"))
        snapshot.match("list_tags_after_remove", tags)

        compatible_versions = aws_client.opensearch.get_compatible_versions(
            DomainName=opensearch_domain_name
        )
        snapshot.match("get_compatible_versions", compatible_versions)

        list_versions = aws_client.opensearch.list_versions()
        snapshot.match("list_versions", list_versions)


class BooksApi(Construct):
    load_books_helper_fn: awslambda.Function
    get_book_fn: awslambda.Function
    list_books_fn: awslambda.Function
    search_book_fn: awslambda.Function
    update_search_cluster_fn: awslambda.Function
    books_table: dynamodb.Table
    opensearch_domain: opensearch.Domain

    LOAD_BOOKS_HELPER_PATH = os.path.join(os.path.dirname(__file__), "functions/loadBooksHelper.js")
    GET_BOOK_PATH = os.path.join(os.path.dirname(__file__), "functions/getBook.js")
    LIST_BOOKS_PATH = os.path.join(os.path.dirname(__file__), "functions/listBooks.js")

    def __init__(
        self,
        stack: cdk.Stack,
        id: str,
        *,
        search_key: str,
        search_update_key: str,
    ):
        super().__init__(stack, id)
        # opensearch
        self.opensearch_domain = opensearch.Domain(
            stack,
            "Domain",
            version=opensearch.EngineVersion.OPENSEARCH_2_5,
            ebs=opensearch.EbsOptions(volume_size=10, volume_type=ec2.EbsDeviceVolumeType.GP2),
            advanced_options={"rest.action.multi.allow_explicit_index": "false"},
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # dynamodb table to store book details
        self.books_table = dynamodb.Table(
            stack,
            "BooksTable",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PROVISIONED,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )
        self.books_table.add_global_secondary_index(
            index_name="category-index",
            partition_key=dynamodb.Attribute(name="category", type=dynamodb.AttributeType.STRING),
            read_capacity=1,
            write_capacity=1,
            projection_type=dynamodb.ProjectionType.ALL,
        )

        self.lambda_role = iam.Role(
            self, "LambdaRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
        )
        self.lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
        )
        self.lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonDynamoDBFullAccess")
        )
        # TODO before updating to Node 20 we need to update function code
        #  since aws-sdk which comes with it is newer version than one bundled with Node 16
        #  lambda for pre-filling the dynamodb
        self.load_books_helper_fn = awslambda.Function(
            stack,
            "LoadBooksLambda",
            handler="index.handler",
            code=awslambda.InlineCode(code=load_file(self.LOAD_BOOKS_HELPER_PATH)),
            runtime=awslambda.Runtime.NODEJS_16_X,
            environment={
                "TABLE_NAME": self.books_table.table_name,
                "S3_BUCKET": S3_BUCKET_BOOKS_INIT,
                "FILE_NAME": S3_KEY_BOOKS_INIT,
            },
            role=self.lambda_role,
        )

        # lambdas to get and list books
        self.get_book_fn = awslambda.Function(
            stack,
            "GetBookLambda",
            handler="index.handler",
            code=awslambda.InlineCode(code=load_file(self.GET_BOOK_PATH)),
            runtime=awslambda.Runtime.NODEJS_16_X,
            environment={
                "TABLE_NAME": self.books_table.table_name,
            },
            role=self.lambda_role,
        )

        self.list_books_fn = awslambda.Function(
            stack,
            "ListBooksLambda",
            handler="index.handler",
            code=awslambda.InlineCode(code=load_file(self.LIST_BOOKS_PATH)),
            runtime=awslambda.Runtime.NODEJS_16_X,
            environment={
                "TABLE_NAME": self.books_table.table_name,
            },
            role=self.lambda_role,
        )

        # lambda to search for book
        bucket = cdk.aws_s3.Bucket.from_bucket_name(
            stack,
            "bucket_name",
            bucket_name=InfraProvisioner.get_asset_bucket_cdk(stack),
        )
        self.search_book_fn = awslambda.Function(
            stack,
            "SearchBookLambda",
            handler="index.handler",
            code=awslambda.S3Code(bucket=bucket, key=search_key),
            runtime=awslambda.Runtime.PYTHON_3_12,
            environment={
                "ESENDPOINT": self.opensearch_domain.domain_endpoint,
            },
            role=self.lambda_role,
        )

        # lambda to update search cluster
        self.update_search_cluster_fn = awslambda.Function(
            stack,
            "UpdateSearchLambda",
            handler="index.handler",
            code=awslambda.S3Code(bucket=bucket, key=search_update_key),
            runtime=awslambda.Runtime.PYTHON_3_12,
            environment={
                "ESENDPOINT": self.opensearch_domain.domain_endpoint,
            },
            role=self.lambda_role,
        )

        event_source = DynamoEventSource(
            table=self.books_table,
            starting_position=awslambda.StartingPosition.TRIM_HORIZON,
            enabled=True,
            batch_size=1,
            retry_attempts=10,
        )
        self.update_search_cluster_fn.add_event_source(event_source)

        self.books_table.grant_write_data(self.load_books_helper_fn)
        self.books_table.grant_read_data(self.get_book_fn)
        self.books_table.grant_read_data(self.list_books_fn)

        self.opensearch_domain.grant_read_write(self.search_book_fn)
        self.opensearch_domain.grant_read_write(self.update_search_cluster_fn)
