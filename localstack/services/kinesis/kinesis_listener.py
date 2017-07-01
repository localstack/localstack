import random
import json
from requests.models import Response
from localstack import constants, config
from localstack.services.awslambda import lambda_api
from localstack.utils.common import to_str


def update_kinesis(method, path, data, headers, response=None, return_forward_info=False):
    action = headers['X-Amz-Target'] if 'X-Amz-Target' in headers else None

    if return_forward_info:
        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            return kinesis_error_response(data)
        return True

    records = []
    if action == constants.KINESIS_ACTION_PUT_RECORD:
        response_body = json.loads(to_str(response.content))
        event_record = {
            'data': data['Data'],
            'partitionKey': data['PartitionKey'],
            'sequenceNumber': response_body.get('SequenceNumber')
        }
        event_records = [event_record]
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(event_records, stream_name)
    elif action == constants.KINESIS_ACTION_PUT_RECORDS:
        event_records = []
        response_body = json.loads(to_str(response.content))
        response_records = response_body['Records']
        records = data['Records']
        for index in range(0, len(records)):
            record = records[index]
            event_record = {
                'data': record['Data'],
                'partitionKey': record['PartitionKey'],
                'sequenceNumber': response_records[index].get('SequenceNumber')
            }
            event_records.append(event_record)
        stream_name = data['StreamName']
        lambda_api.process_kinesis_records(event_records, stream_name)


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
