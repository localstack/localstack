import json
from base64 import b64decode


def _process_kinesis_records(event):
    for record in event["Records"]:
        raw_data = record["kinesis"]["data"]
        parsed_data = b64decode(raw_data.encode())
        yield json.loads(parsed_data.decode())


def handler(event, context):
    records_data = list(_process_kinesis_records(event))
    print(json.dumps(records_data))
