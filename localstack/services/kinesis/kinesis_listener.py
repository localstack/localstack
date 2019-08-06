import json
import random
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
ACTION_UPDATE_SHARD_COUNT = '%s.UpdateShardCount' % ACTION_PREFIX


class ProxyListenerKinesis(ProxyListener):

    def forward_request(self, method, path, data, headers):
        data = json.loads(to_str(data))
        action = headers.get('X-Amz-Target')

        if action == '%s.DescribeStreamSummary' % ACTION_PREFIX:
            stream_arn = data.get('StreamARN') or data['StreamName']
            # TODO fix values below
            result = {
                'StreamDescriptionSummary': {
                    'ConsumerCount': 0,
                    'EnhancedMonitoring': [],
                    'KeyId': 'string',
                    'OpenShardCount': 0,
                    'RetentionPeriodHours': 1,
                    'StreamARN': stream_arn,
                    # 'StreamCreationTimestamp': number,
                    'StreamName': data['StreamName'],
                    'StreamStatus': 'ACTIVE'
                }
            }
            return result
        if action == '%s.DescribeStreamConsumer' % ACTION_PREFIX:
            consumer_arn = data.get('ConsumerARN') or data['ConsumerName']
            consumer_name = data.get('ConsumerName') or data['ConsumerARN']
            result = {
                'ConsumerDescription': {
                    'ConsumerARN': consumer_arn,
                    # 'ConsumerCreationTimestamp': number,
                    'ConsumerName': consumer_name,
                    'ConsumerStatus': 'ACTIVE',
                    'StreamARN': data.get('StreamARN')
                }
            }
            return result

        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            action = headers.get('X-Amz-Target')
            if action in [ACTION_PUT_RECORD, ACTION_PUT_RECORDS]:
                return kinesis_error_response(data, action)
        return True

    def return_response(self, method, path, data, headers, response):
        action = headers.get('X-Amz-Target')
        data = json.loads(to_str(data))

        records = []
        if action in (ACTION_CREATE_STREAM, ACTION_DELETE_STREAM):
            event_type = (event_publisher.EVENT_KINESIS_CREATE_STREAM if action == ACTION_CREATE_STREAM
                          else event_publisher.EVENT_KINESIS_DELETE_STREAM)
            payload = {'n': event_publisher.get_hash(data.get('StreamName'))}
            if action == ACTION_CREATE_STREAM:
                payload['s'] = data.get('ShardCount')
            event_publisher.fire_event(event_type, payload=payload)
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
            if 'Records' in response_body:
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
        elif action == ACTION_UPDATE_SHARD_COUNT:
            # Currently kinesalite, which backs the Kinesis implementation for localstack, does
            # not support UpdateShardCount:
            # https://github.com/mhart/kinesalite/issues/61
            #
            # [Terraform](https://www.terraform.io) makes the call to UpdateShardCount when it
            # applies Kinesis resources. A Terraform run fails when this is not present.
            #
            # The code that follows just returns a successful response, bypassing the 400
            # response that kinesalite returns.
            #
            response = Response()
            response.status_code = 200
            content = {
                'CurrentShardCount': 1,
                'StreamName': data['StreamName'],
                'TargetShardCount': data['TargetShardCount']
            }
            response.encoding = 'UTF-8'
            response._content = json.dumps(content)
            return response


# instantiate listener
UPDATE_KINESIS = ProxyListenerKinesis()


def kinesis_error_response(data, action):
    error_response = Response()

    if action == ACTION_PUT_RECORD:
        error_response.status_code = 400
        content = {
            'ErrorCode': 'ProvisionedThroughputExceededException',
            'ErrorMessage': 'Rate exceeded for shard X in stream Y under account Z.'
        }
    else:
        error_response.status_code = 200
        content = {'FailedRecordCount': 1, 'Records': []}
        for record in data.get('Records', []):
            content['Records'].append({
                'ErrorCode': 'ProvisionedThroughputExceededException',
                'ErrorMessage': 'Rate exceeded for shard X in stream Y under account Z.'
            })

    error_response._content = json.dumps(content)
    return error_response
