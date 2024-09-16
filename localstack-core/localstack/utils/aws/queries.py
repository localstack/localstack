from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import extract_region_from_arn, sqs_queue_url_for_arn
from localstack.utils.strings import to_str


def sqs_receive_message(queue_arn):
    region_name = extract_region_from_arn(queue_arn)
    client = connect_to(region_name=region_name).sqs
    queue_url = sqs_queue_url_for_arn(queue_arn)
    response = client.receive_message(QueueUrl=queue_url)
    return response


def kinesis_get_latest_records(
    stream_name: str, shard_id: str, count: int = 10, client=None
) -> list[dict]:
    kinesis = client or connect_to().kinesis
    result = []
    response = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )
    shard_iterator = response["ShardIterator"]
    while shard_iterator:
        records_response = kinesis.get_records(ShardIterator=shard_iterator)
        records = records_response["Records"]
        for record in records:
            try:
                record["Data"] = to_str(record["Data"])
            except Exception:
                pass
        result.extend(records)
        shard_iterator = records_response["NextShardIterator"] if records else False
        while len(result) > count:
            result.pop(0)
    return result
