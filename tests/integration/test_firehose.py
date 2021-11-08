import base64
import json

from localstack import config
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import lambda_function_arn
from localstack.utils.common import (
    get_free_tcp_port,
    get_service_protocol,
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


def test_firehose_http():
    class MyUpdateListener(ProxyListener):
        def forward_request(self, method, path, data, headers):
            data_received = dict(json.loads(data.decode("utf-8")))
            records.append(data_received)
            return 200

    # create processor func
    func_name = f"proc-{short_uid()}"
    testutil.create_lambda_function(handler_file=PROCESSOR_LAMBDA, func_name=func_name)

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
        "ProcessingConfiguration": {
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
        },
    }

    # start proxy server
    start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
    wait_for_port_open(local_port)

    # create firehose stream with http destination
    firehose = aws_stack.connect_to_service("firehose")
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
        assert received_record_data == f"{msg_text}-processed"

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
