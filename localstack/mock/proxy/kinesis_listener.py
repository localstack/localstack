import random
import json
from requests.models import Response
from localstack import constants, config
from localstack.mock.apis import lambda_api


def update_kinesis(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            return kinesis_error_response(data)
        else:
            return True

    action = headers['X-Amz-Target'] if 'X-Amz-Target' in headers else None
    records = []
    if action == constants.KINESIS_ACTION_PUT_RECORD:
        record = {
            'data': data['Data'],
            'partitionKey': data['PartitionKey']
        }
        records = [record]
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(records, stream_name)
    elif action == constants.KINESIS_ACTION_PUT_RECORDS:
        records = []
        for record in data['Records']:
            record = {
                'data': record['Data'],
                'partitionKey': record['PartitionKey']
            }
            records.append(record)
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(records, stream_name)


def kinesis_error_response(data):
    error_response = Response()
    error_response.status_code = 200
    content = {"FailedRecordCount": 1, "Records": []}
    for record in data["Records"]:
        content["Records"].append({
            "ErrorCode": "ProvisionedThroughputExceededException",
            "ErrorMessage": "Rate exceeded for shard X in stream Y under account Z."
        })
    error_response._content = json.dumps(content)
    return error_response
