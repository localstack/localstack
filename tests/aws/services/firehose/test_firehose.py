import base64
import json
import time

import pytest as pytest
import requests
from pytest_httpserver import HTTPServer

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import poll_condition, retry
from tests.aws.services.firehose.helper_functions import get_firehose_iam_documents

PROCESSOR_LAMBDA = """
def handler(event, context):
    import base64
    records = event.get("records", [])
    for i in range(len(records)):
        # assert that metadata are contained in the records
        assert "approximateArrivalTimestamp" in records[i]
        assert "kinesisRecordMetadata" in records[i]
        assert records[i]["kinesisRecordMetadata"]["shardId"]
        assert records[i]["kinesisRecordMetadata"]["partitionKey"]
        assert records[i]["kinesisRecordMetadata"]["approximateArrivalTimestamp"]
        assert records[i]["kinesisRecordMetadata"]["sequenceNumber"]
        # convert record data
        data = records[i].get("data")
        data = base64.b64decode(data) + b"-processed"
        records[i]["data"] = base64.b64encode(data).decode("utf-8")
    return {"records": records}
"""

TEST_MESSAGE = "Test-message-2948294kdlsie"


@pytest.mark.parametrize("lambda_processor_enabled", [True, False])
@markers.aws.unknown
def test_kinesis_firehose_http(
    aws_client,
    lambda_processor_enabled: bool,
    create_lambda_function,
    httpserver: HTTPServer,
    cleanups,
):
    httpserver.expect_request("").respond_with_data(b"", 200)
    http_endpoint = httpserver.url_for("/")
    if lambda_processor_enabled:
        # create processor func
        func_name = f"proc-{short_uid()}"
        func_arn = create_lambda_function(handler_file=PROCESSOR_LAMBDA, func_name=func_name)[
            "CreateFunctionResponse"
        ]["FunctionArn"]

    # define firehose configs
    http_destination_update = {
        "EndpointConfiguration": {"Url": http_endpoint, "Name": "test_update"}
    }
    http_destination = {
        "EndpointConfiguration": {"Url": http_endpoint},
        "S3BackupMode": "FailedDataOnly",
        "S3Configuration": {
            "RoleARN": "arn:.*",
            "BucketARN": "arn:.*",
            "Prefix": "",
            "ErrorOutputPrefix": "",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    }

    if lambda_processor_enabled:
        http_destination["ProcessingConfiguration"] = {
            "Enabled": True,
            "Processors": [
                {
                    "Type": "Lambda",
                    "Parameters": [
                        {
                            "ParameterName": "LambdaArn",
                            "ParameterValue": func_arn,
                        }
                    ],
                }
            ],
        }

    # create firehose stream with http destination
    firehose = aws_client.firehose
    stream_name = "firehose_" + short_uid()
    stream = firehose.create_delivery_stream(
        DeliveryStreamName=stream_name,
        HttpEndpointDestinationConfiguration=http_destination,
    )
    assert stream
    cleanups.append(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    stream_description = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
    stream_description = stream_description["DeliveryStreamDescription"]
    destination_description = stream_description["Destinations"][0][
        "HttpEndpointDestinationDescription"
    ]
    assert len(stream_description["Destinations"]) == 1
    assert destination_description["EndpointConfiguration"]["Url"] == http_endpoint

    # put record
    msg_text = "Hello World!"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": msg_text})

    # wait for the result to arrive with proper content
    assert poll_condition(lambda: len(httpserver.log) >= 1, timeout=5)
    request, _ = httpserver.log[0]
    record = request.get_json(force=True)
    received_record = record["records"][0]
    received_record_data = to_str(base64.b64decode(to_bytes(received_record["data"])))
    assert received_record_data == f"{msg_text}{'-processed' if lambda_processor_enabled else ''}"

    # update stream destination
    destination_id = stream_description["Destinations"][0]["DestinationId"]
    version_id = stream_description["VersionId"]
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        DestinationId=destination_id,
        CurrentDeliveryStreamVersionId=version_id,
        HttpEndpointDestinationUpdate=http_destination_update,
    )
    stream_description = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
    stream_description = stream_description["DeliveryStreamDescription"]
    destination_description = stream_description["Destinations"][0][
        "HttpEndpointDestinationDescription"
    ]
    assert destination_description["EndpointConfiguration"]["Name"] == "test_update"


class TestFirehoseIntegration:
    @markers.skip_offline
    @markers.aws.unknown
    @pytest.mark.skip(reason="flaky")
    def test_kinesis_firehose_elasticsearch_s3_backup(
        self,
        s3_bucket,
        kinesis_create_stream,
        cleanups,
        aws_client,
        account_id,
    ):
        domain_name = f"test-domain-{short_uid()}"
        stream_name = f"test-stream-{short_uid()}"
        role_arn = f"arn:aws:iam::{account_id}:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        es_create_response = aws_client.es.create_elasticsearch_domain(DomainName=domain_name)
        cleanups.append(lambda: aws_client.es.delete_elasticsearch_domain(DomainName=domain_name))
        es_url = f"http://{es_create_response['DomainStatus']['Endpoint']}"
        es_arn = es_create_response["DomainStatus"]["ARN"]

        # create s3 backup bucket arn
        bucket_arn = arns.s3_bucket_arn(s3_bucket)

        # create kinesis stream
        kinesis_create_stream(StreamName=stream_name, ShardCount=2)
        stream_info = aws_client.kinesis.describe_stream(StreamName=stream_name)
        stream_arn = stream_info["StreamDescription"]["StreamARN"]

        kinesis_stream_source_def = {
            "KinesisStreamARN": stream_arn,
            "RoleARN": role_arn,
        }
        elasticsearch_destination_configuration = {
            "RoleARN": role_arn,
            "DomainARN": es_arn,
            "IndexName": "activity",
            "TypeName": "activity",
            "S3BackupMode": "AllDocuments",
            "S3Configuration": {
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
            },
        }
        aws_client.firehose.create_delivery_stream(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration=kinesis_stream_source_def,
            ElasticsearchDestinationConfiguration=elasticsearch_destination_configuration,
        )
        cleanups.append(
            lambda: aws_client.firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
        )

        # wait for delivery stream to be ready
        def check_stream_state():
            stream = aws_client.firehose.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

        assert poll_condition(check_stream_state, 45, 1)

        # wait for ES cluster to be ready
        def check_domain_state():
            result = aws_client.es.describe_elasticsearch_domain(DomainName=domain_name)
            return not result["DomainStatus"]["Processing"]

        # if ElasticSearch is not yet installed, it might take some time to download the package before starting the domain
        assert poll_condition(check_domain_state, 120, 1)

        # put kinesis stream record
        kinesis_record = {"target": "hello"}
        aws_client.kinesis.put_record(
            StreamName=stream_name, Data=to_bytes(json.dumps(kinesis_record)), PartitionKey="1"
        )

        firehose_record = {"target": "world"}
        aws_client.firehose.put_record(
            DeliveryStreamName=delivery_stream_name,
            Record={"Data": to_bytes(json.dumps(firehose_record))},
        )

        def assert_elasticsearch_contents():
            response = requests.get(f"{es_url}/activity/_search")
            response_bod = response.json()
            assert "hits" in response_bod
            response_bod_hits = response_bod["hits"]
            assert "hits" in response_bod_hits
            result = response_bod_hits["hits"]
            assert len(result) == 2
            sources = [item["_source"] for item in result]
            assert firehose_record in sources
            assert kinesis_record in sources

        retry(assert_elasticsearch_contents)

        def assert_s3_contents():
            result = aws_client.s3.list_objects(Bucket=s3_bucket)
            contents = []
            for o in result.get("Contents"):
                data = aws_client.s3.get_object(Bucket=s3_bucket, Key=o.get("Key"))
                content = data["Body"].read()
                contents.append(content)
            assert len(contents) == 2
            assert to_bytes(json.dumps(firehose_record)) in contents
            assert to_bytes(json.dumps(kinesis_record)) in contents

        retry(assert_s3_contents)

    @markers.skip_offline
    @pytest.mark.parametrize("opensearch_endpoint_strategy", ["domain", "path", "port"])
    @markers.aws.unknown
    @pytest.mark.skip(reason="flaky")
    def test_kinesis_firehose_opensearch_s3_backup(
        self,
        s3_bucket,
        kinesis_create_stream,
        monkeypatch,
        opensearch_endpoint_strategy,
        aws_client,
        account_id,
    ):
        domain_name = f"test-domain-{short_uid()}"
        stream_name = f"test-stream-{short_uid()}"
        role_arn = f"arn:aws:iam::{account_id}:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", opensearch_endpoint_strategy)
        try:
            opensearch_create_response = aws_client.opensearch.create_domain(DomainName=domain_name)
            opensearch_url = f"http://{opensearch_create_response['DomainStatus']['Endpoint']}"
            opensearch_arn = opensearch_create_response["DomainStatus"]["ARN"]

            # create s3 backup bucket arn
            bucket_arn = arns.s3_bucket_arn(s3_bucket)

            # create kinesis stream
            kinesis_create_stream(StreamName=stream_name, ShardCount=2)
            stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
                "StreamDescription"
            ]["StreamARN"]

            kinesis_stream_source_def = {
                "KinesisStreamARN": stream_arn,
                "RoleARN": role_arn,
            }
            opensearch_destination_configuration = {
                "RoleARN": role_arn,
                "DomainARN": opensearch_arn,
                "IndexName": "activity",
                "TypeName": "activity",
                "S3BackupMode": "AllDocuments",
                "S3Configuration": {
                    "RoleARN": role_arn,
                    "BucketARN": bucket_arn,
                },
            }
            aws_client.firehose.create_delivery_stream(
                DeliveryStreamName=delivery_stream_name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration=kinesis_stream_source_def,
                AmazonopensearchserviceDestinationConfiguration=opensearch_destination_configuration,
            )

            # wait for delivery stream to be ready
            def check_stream_state():
                stream = aws_client.firehose.describe_delivery_stream(
                    DeliveryStreamName=delivery_stream_name
                )
                return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

            assert poll_condition(check_stream_state, 60, 1)

            # wait for opensearch cluster to be ready
            def check_domain_state():
                result = aws_client.opensearch.describe_domain(DomainName=domain_name)[
                    "DomainStatus"
                ]["Processing"]
                return not result

            # if OpenSearch is not yet installed, it might take some time to download the package before starting the domain
            assert poll_condition(check_domain_state, 120, 1)

            # put kinesis stream record
            kinesis_record = {"target": "hello"}
            aws_client.kinesis.put_record(
                StreamName=stream_name, Data=to_bytes(json.dumps(kinesis_record)), PartitionKey="1"
            )

            firehose_record = {"target": "world"}
            aws_client.firehose.put_record(
                DeliveryStreamName=delivery_stream_name,
                Record={"Data": to_bytes(json.dumps(firehose_record))},
            )

            def assert_opensearch_contents():
                response = requests.get(f"{opensearch_url}/activity/_search")
                response_bod = response.json()
                assert "hits" in response_bod
                response_bod_hits = response_bod["hits"]
                assert "hits" in response_bod_hits
                result = response_bod_hits["hits"]
                assert len(result) == 2
                sources = [item["_source"] for item in result]
                assert firehose_record in sources
                assert kinesis_record in sources

            retry(assert_opensearch_contents)

            def assert_s3_contents():
                result = aws_client.s3.list_objects(Bucket=s3_bucket)
                contents = []
                for o in result.get("Contents"):
                    data = aws_client.s3.get_object(Bucket=s3_bucket, Key=o.get("Key"))
                    content = data["Body"].read()
                    contents.append(content)
                assert len(contents) == 2
                assert to_bytes(json.dumps(firehose_record)) in contents
                assert to_bytes(json.dumps(kinesis_record)) in contents

            retry(assert_s3_contents)

        finally:
            aws_client.firehose.delete_delivery_stream(DeliveryStreamName=delivery_stream_name)
            aws_client.opensearch.delete_domain(DomainName=domain_name)

    @markers.aws.unknown
    def test_kinesis_firehose_kinesis_as_source(
        self, s3_bucket, kinesis_create_stream, cleanups, aws_client, account_id
    ):
        bucket_arn = arns.s3_bucket_arn(s3_bucket)
        stream_name = f"test-stream-{short_uid()}"
        log_group_name = f"group{short_uid()}"
        role_arn = f"arn:aws:iam::{account_id}:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"

        kinesis_create_stream(StreamName=stream_name, ShardCount=2)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        response = aws_client.firehose.create_delivery_stream(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration={
                "KinesisStreamARN": stream_arn,
                "RoleARN": role_arn,
            },
            ExtendedS3DestinationConfiguration={
                "BucketARN": bucket_arn,
                "RoleARN": role_arn,
                "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 64},
                "DynamicPartitioningConfiguration": {"Enabled": True},
                "ProcessingConfiguration": {
                    "Enabled": True,
                    "Processors": [
                        {
                            "Type": "MetadataExtraction",
                            "Parameters": [
                                {
                                    "ParameterName": "MetadataExtractionQuery",
                                    "ParameterValue": "{s3Prefix: .tableName}",
                                },
                                {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
                            ],
                        },
                    ],
                },
                "DataFormatConversionConfiguration": {"Enabled": True},
                "CompressionFormat": "GZIP",
                "Prefix": "firehoseTest/!{partitionKeyFromQuery:s3Prefix}/!{partitionKeyFromLambda:companyId}/!{partitionKeyFromLambda:year}/!{partitionKeyFromLambda:month}/",
                "ErrorOutputPrefix": "firehoseTest-errors/!{firehose:error-output-type}/",
                "CloudWatchLoggingOptions": {
                    "Enabled": True,
                    "LogGroupName": log_group_name,
                },
            },
        )
        cleanups.append(
            lambda: aws_client.firehose.delete_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # make sure the stream will come up at some point, for cleaner cleanup
        def check_stream_state():
            stream = aws_client.firehose.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

        assert poll_condition(check_stream_state, 45, 1)

    @markers.aws.validated
    def test_kinesis_firehose_kinesis_as_source_multiple_delivery_streams(
        self,
        s3_create_bucket,
        kinesis_create_stream,
        create_iam_role_with_policy,
        wait_for_stream_ready,
        firehose_create_delivery_stream,
        read_s3_data,
        snapshot,
        aws_client,
    ):
        # create s3 bucket a and b
        bucket_a_name = f"test-bucket-a-{short_uid()}"
        s3_create_bucket(Bucket=bucket_a_name)
        bucket_a_arn = arns.s3_bucket_arn(bucket_a_name)
        bucket_b_name = f"test-bucket-b-{short_uid()}"
        s3_create_bucket(Bucket=bucket_b_name)
        bucket_b_arn = arns.s3_bucket_arn(bucket_b_name)

        # create kinesis stream
        stream_name = f"test-stream-{short_uid()}"
        kinesis_create_stream(
            StreamName=stream_name,
            ShardCount=1,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
        )
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        # create IAM role and policy
        role_document, policy_document = get_firehose_iam_documents(
            [bucket_a_arn, bucket_b_arn], stream_arn
        )
        role_arn = create_iam_role_with_policy(
            RoleDefinition=role_document, PolicyDefinition=policy_document
        )
        # required for role propagation delay on aws
        if is_aws_cloud():
            time.sleep(10)
        wait_for_stream_ready(stream_name)

        # create log groupe for firehose delivery stream error logging
        log_group_name = f"group-{short_uid()}"
        aws_client.logs.create_log_group(
            logGroupName=log_group_name,
        )

        # create firehose streams & subscribe to kinesis
        delivery_stream_a_name = f"test-delivery-stream-a-{short_uid()}"
        delivery_stream_b_name = f"test-delivery-stream-b-{short_uid()}"

        for bucket_arn, delivery_stream_name in [
            (bucket_a_arn, delivery_stream_a_name),
            (bucket_b_arn, delivery_stream_b_name),
        ]:
            extended_s3_destination_configuration = {
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
                "Prefix": "firehoseTest",
                "ErrorOutputPrefix": "firehoseTest-errors/!{firehose:error-output-type}/",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 1},
                "CompressionFormat": "UNCOMPRESSED",
                "EncryptionConfiguration": {"NoEncryptionConfig": "NoEncryption"},
                "CloudWatchLoggingOptions": {
                    "Enabled": True,
                    "LogGroupName": log_group_name,
                    "LogStreamName": f"stream-{short_uid()}",
                },
            }

            firehose_create_delivery_stream(
                DeliveryStreamName=delivery_stream_name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration={
                    "KinesisStreamARN": stream_arn,
                    "RoleARN": role_arn,
                },
                ExtendedS3DestinationConfiguration=extended_s3_destination_configuration,
            )

        # put message to kinesis event stream
        record_data = TEST_MESSAGE
        aws_client.kinesis.put_record(
            StreamName=stream_name,
            Data=record_data,
            PartitionKey="1",
        )

        # poll file from s3 buckets
        s3_data = dict()
        for bucket_name in [bucket_a_name, bucket_b_name]:
            s3_data_bucket = read_s3_data(bucket_name, timeout=300)
            assert len(s3_data_bucket.keys()) == 1
            assert record_data == next(iter(s3_data_bucket.values()))
            s3_data_bucket = {"folder-name": s3_data_bucket.popitem()[1]}
            s3_data[bucket_name] = s3_data_bucket

        snapshot.add_transformer(
            [
                snapshot.transform.regex(bucket_a_name, "<bucket-a>"),
                snapshot.transform.regex(bucket_b_name, "<bucket-b>"),
            ]
        )
        snapshot.match("kinesis-event-stream-multiple-delivery-streams", s3_data)

    @markers.aws.validated
    def test_kinesis_firehose_s3_as_destination_with_file_extension(
        self,
        s3_bucket,
        aws_client,
        account_id,
        firehose_create_delivery_stream,
        create_iam_role_with_policy,
    ):
        bucket_arn = arns.s3_bucket_arn(s3_bucket)
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        file_extension = ".txt"

        role_policy, policy_document = get_firehose_iam_documents(bucket_arn, "*")

        role_arn = create_iam_role_with_policy(
            RoleDefinition=role_policy, PolicyDefinition=policy_document
        )

        if is_aws_cloud():
            time.sleep(10)  # AWS IAM propagation delay

        firehose_create_delivery_stream(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "BucketARN": bucket_arn,
                "RoleARN": role_arn,
                "FileExtension": file_extension,
                "ErrorOutputPrefix": "errors",
            },
        )

        # prepare sample message
        data = base64.b64encode(TEST_MESSAGE.encode())
        record = {"Data": data}

        def assert_s3_contents():
            aws_client.firehose.put_record(
                DeliveryStreamName=delivery_stream_name,
                Record=record,
            )
            s3_objects = aws_client.s3.list_objects(Bucket=s3_bucket)["Contents"]
            s3_object = s3_objects[0]
            assert s3_object["Key"].endswith(file_extension)

        retry_options = {"sleep": 1, "retries": 10, "sleep_before": 1}

        if is_aws_cloud():
            retry_options["retries"] = 600
            retry_options["sleep"] = 5
            retry_options["sleep_before"] = 10

        retry(assert_s3_contents, **retry_options)
