import base64
import json

import pytest as pytest
import requests

from localstack import config
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.utils.aws import arns, aws_stack
from localstack.utils.aws.arns import lambda_function_arn
from localstack.utils.common import (
    get_free_tcp_port,
    get_service_protocol,
    poll_condition,
    retry,
    short_uid,
    to_bytes,
    to_str,
    wait_for_port_open,
)

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


@pytest.mark.parametrize("lambda_processor_enabled", [True, False])
def test_firehose_http(lambda_processor_enabled: bool, create_lambda_function):
    class MyUpdateListener(ProxyListener):
        def forward_request(self, method, path, data, headers):
            data_received = dict(json.loads(data.decode("utf-8")))
            records.append(data_received)
            return 200

    if lambda_processor_enabled:
        # create processor func
        func_name = f"proc-{short_uid()}"
        create_lambda_function(handler_file=PROCESSOR_LAMBDA, func_name=func_name)

    # define firehose configs
    local_port = get_free_tcp_port()
    endpoint = "{}://{}:{}".format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, local_port)
    records = []
    http_destination_update = {"EndpointConfiguration": {"Url": endpoint, "Name": "test_update"}}
    http_destination = {
        "EndpointConfiguration": {"Url": endpoint},
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
                            "ParameterValue": lambda_function_arn(func_name),
                        }
                    ],
                }
            ],
        }

    # start proxy server
    start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
    wait_for_port_open(local_port)

    # create firehose stream with http destination
    firehose = aws_stack.create_external_boto_client("firehose")
    stream_name = "firehose_" + short_uid()
    stream = firehose.create_delivery_stream(
        DeliveryStreamName=stream_name,
        HttpEndpointDestinationConfiguration=http_destination,
    )
    assert stream
    stream_description = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
    stream_description = stream_description["DeliveryStreamDescription"]
    destination_description = stream_description["Destinations"][0][
        "HttpEndpointDestinationDescription"
    ]
    assert len(stream_description["Destinations"]) == 1
    assert (
        destination_description["EndpointConfiguration"]["Url"] == f"http://localhost:{local_port}"
    )

    # put record
    msg_text = "Hello World!"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": msg_text})

    # wait for the result to arrive with proper content
    def _assert_record():
        received_record = records[0]["records"][0]
        received_record_data = to_str(base64.b64decode(to_bytes(received_record["data"])))
        assert (
            received_record_data == f"{msg_text}{'-processed' if lambda_processor_enabled else ''}"
        )

    retry(_assert_record, retries=5, sleep=1)

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

    # delete stream
    stream = firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    assert stream["ResponseMetadata"]["HTTPStatusCode"] == 200


class TestFirehoseIntegration:
    @pytest.mark.skip_offline
    @pytest.mark.parametrize("opensearch_endpoint_strategy", ["domain", "path"])
    def test_kinesis_firehose_elasticsearch_s3_backup(
        self,
        firehose_client,
        kinesis_client,
        es_client,
        s3_client,
        s3_bucket,
        kinesis_create_stream,
        monkeypatch,
        opensearch_endpoint_strategy,
        cleanups,
    ):
        domain_name = f"test-domain-{short_uid()}"
        stream_name = f"test-stream-{short_uid()}"
        role_arn = "arn:aws:iam::000000000000:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", opensearch_endpoint_strategy)
        es_create_response = es_client.create_elasticsearch_domain(DomainName=domain_name)
        cleanups.append(lambda: es_client.delete_elasticsearch_domain(DomainName=domain_name))
        es_url = f"http://{es_create_response['DomainStatus']['Endpoint']}"
        es_arn = es_create_response["DomainStatus"]["ARN"]

        # create s3 backup bucket arn
        bucket_arn = arns.s3_bucket_arn(s3_bucket)

        # create kinesis stream
        kinesis_create_stream(StreamName=stream_name, ShardCount=2)
        stream_info = kinesis_client.describe_stream(StreamName=stream_name)
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
        firehose_client.create_delivery_stream(
            DeliveryStreamName=delivery_stream_name,
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration=kinesis_stream_source_def,
            ElasticsearchDestinationConfiguration=elasticsearch_destination_configuration,
        )
        cleanups.append(
            lambda: firehose_client.delete_delivery_stream(DeliveryStreamName=stream_name)
        )

        # wait for delivery stream to be ready
        def check_stream_state():
            stream = firehose_client.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

        assert poll_condition(check_stream_state, 45, 1)

        # wait for ES cluster to be ready
        def check_domain_state():
            result = es_client.describe_elasticsearch_domain(DomainName=domain_name)
            return not result["DomainStatus"]["Processing"]

        assert poll_condition(check_domain_state, 30, 1)

        # put kinesis stream record
        kinesis_record = {"target": "hello"}
        kinesis_client.put_record(
            StreamName=stream_name, Data=to_bytes(json.dumps(kinesis_record)), PartitionKey="1"
        )

        firehose_record = {"target": "world"}
        firehose_client.put_record(
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
            result = s3_client.list_objects(Bucket=s3_bucket)
            contents = []
            for o in result.get("Contents"):
                data = s3_client.get_object(Bucket=s3_bucket, Key=o.get("Key"))
                content = data["Body"].read()
                contents.append(content)
            assert len(contents) == 2
            assert to_bytes(json.dumps(firehose_record)) in contents
            assert to_bytes(json.dumps(kinesis_record)) in contents

        retry(assert_s3_contents)

    @pytest.mark.skip_offline
    @pytest.mark.parametrize("opensearch_endpoint_strategy", ["domain", "path"])
    def test_kinesis_firehose_opensearch_s3_backup(
        self,
        firehose_client,
        kinesis_client,
        opensearch_client,
        s3_client,
        s3_bucket,
        kinesis_create_stream,
        monkeypatch,
        opensearch_endpoint_strategy,
    ):
        domain_name = f"test-domain-{short_uid()}"
        stream_name = f"test-stream-{short_uid()}"
        role_arn = "arn:aws:iam::000000000000:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", opensearch_endpoint_strategy)
        try:
            opensearch_create_response = opensearch_client.create_domain(DomainName=domain_name)
            opensearch_url = f"http://{opensearch_create_response['DomainStatus']['Endpoint']}"
            opensearch_arn = opensearch_create_response["DomainStatus"]["ARN"]

            # create s3 backup bucket arn
            bucket_arn = arns.s3_bucket_arn(s3_bucket)

            # create kinesis stream
            kinesis_create_stream(StreamName=stream_name, ShardCount=2)
            stream_arn = kinesis_client.describe_stream(StreamName=stream_name)[
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
            firehose_client.create_delivery_stream(
                DeliveryStreamName=delivery_stream_name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration=kinesis_stream_source_def,
                AmazonopensearchserviceDestinationConfiguration=opensearch_destination_configuration,
            )

            # wait for delivery stream to be ready
            def check_stream_state():
                stream = firehose_client.describe_delivery_stream(
                    DeliveryStreamName=delivery_stream_name
                )
                return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

            assert poll_condition(check_stream_state, 30, 1)

            # wait for opensearch cluster to be ready
            def check_domain_state():
                result = opensearch_client.describe_domain(DomainName=domain_name)["DomainStatus"][
                    "Processing"
                ]
                return not result

            assert poll_condition(check_domain_state, 30, 1)

            # put kinesis stream record
            kinesis_record = {"target": "hello"}
            kinesis_client.put_record(
                StreamName=stream_name, Data=to_bytes(json.dumps(kinesis_record)), PartitionKey="1"
            )

            firehose_record = {"target": "world"}
            firehose_client.put_record(
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
                result = s3_client.list_objects(Bucket=s3_bucket)
                contents = []
                for o in result.get("Contents"):
                    data = s3_client.get_object(Bucket=s3_bucket, Key=o.get("Key"))
                    content = data["Body"].read()
                    contents.append(content)
                assert len(contents) == 2
                assert to_bytes(json.dumps(firehose_record)) in contents
                assert to_bytes(json.dumps(kinesis_record)) in contents

            retry(assert_s3_contents)

        finally:
            firehose_client.delete_delivery_stream(DeliveryStreamName=delivery_stream_name)
            opensearch_client.delete_domain(DomainName=domain_name)

    def test_delivery_stream_with_kinesis_as_source(
        self,
        firehose_client,
        kinesis_client,
        s3_client,
        s3_bucket,
        kinesis_create_stream,
        cleanups,
    ):

        bucket_arn = arns.s3_bucket_arn(s3_bucket)
        stream_name = f"test-stream-{short_uid()}"
        log_group_name = f"group{short_uid()}"
        role_arn = "arn:aws:iam::000000000000:role/Firehose-Role"
        delivery_stream_name = f"test-delivery-stream-{short_uid()}"

        kinesis_create_stream(StreamName=stream_name, ShardCount=2)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]

        response = firehose_client.create_delivery_stream(
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
            lambda: firehose_client.delete_delivery_stream(DeliveryStreamName=delivery_stream_name)
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # make sure the stream will come up at some point, for cleaner cleanup
        def check_stream_state():
            stream = firehose_client.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name
            )
            return stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

        assert poll_condition(check_stream_state, 45, 1)
