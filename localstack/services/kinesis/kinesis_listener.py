import random
import json
from requests.models import Response
from localstack import config
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener

# action headers
ACTION_PREFIX = 'Kinesis_20131202'
ACTION_PUT_RECORD = '%s.PutRecord' % ACTION_PREFIX
ACTION_PUT_RECORDS = '%s.PutRecords' % ACTION_PREFIX
ACTION_CREATE_STREAM = '%s.CreateStream' % ACTION_PREFIX
ACTION_DELETE_STREAM = '%s.DeleteStream' % ACTION_PREFIX


class ProxyListenerKinesis(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            return kinesis_error_response(data)
        return True

    def return_response(self, method, path, data, headers, response):
        action = headers.get('X-Amz-Target')

        records = []
        if action in (ACTION_CREATE_STREAM, ACTION_DELETE_STREAM):
            event_type = (event_publisher.EVENT_KINESIS_CREATE_STREAM if action == ACTION_CREATE_STREAM
                else event_publisher.EVENT_KINESIS_DELETE_STREAM)
            event_publisher.fire_event(event_type, payload={'n': event_publisher.get_hash(data.get('StreamName'))})
        elif action == ACTION_PUT_RECORD:
            response_body = json.loads(to_str(response.content))
            event_record = {
                'data': data['Data'],
                'partitionKey': data['PartitionKey'],
                'sequenceNumber': response_body.get('SequenceNumber')
            }
            event_records = [event_record]
            stream_name = data['StreamName']
            lambda_api.process_kinesis_records(event_records, stream_name)
        elif action == ACTION_PUT_RECORDS:
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


# instantiate listener
UPDATE_KINESIS = ProxyListenerKinesis()


def kinesis_error_response(data):
    error_response = Response()
    error_response.status_code = 200
    content = {'FailedRecordCount': 1, 'Records': []}
    for record in data['Records']:
        content['Records'].append({
            'ErrorCode': 'ProvisionedThroughputExceededException',
            'ErrorMessage': 'Rate exceeded for shard X in stream Y under account Z.'
        })
    error_response._content = json.dumps(content)
    return error_response
