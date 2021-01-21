import re
import json
import random
import cbor2
import base64
from requests.models import Response
from localstack import config
from localstack.constants import APPLICATION_JSON, APPLICATION_CBOR
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, json_safe, clone, epoch_timestamp, now_utc
from localstack.utils.analytics import event_publisher
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener

# action headers
ACTION_PREFIX = 'Kinesis_20131202'
ACTION_PUT_RECORD = '%s.PutRecord' % ACTION_PREFIX
ACTION_PUT_RECORDS = '%s.PutRecords' % ACTION_PREFIX
ACTION_LIST_STREAMS = '%s.ListStreams' % ACTION_PREFIX
ACTION_CREATE_STREAM = '%s.CreateStream' % ACTION_PREFIX
ACTION_DELETE_STREAM = '%s.DeleteStream' % ACTION_PREFIX
ACTION_UPDATE_SHARD_COUNT = '%s.UpdateShardCount' % ACTION_PREFIX
ACTION_GET_RECORDS = '%s.GetRecords' % ACTION_PREFIX

# list of stream consumer details
STREAM_CONSUMERS = []


class ProxyListenerKinesis(ProxyListener):

    def forward_request(self, method, path, data, headers):
        global STREAM_CONSUMERS
        data = self.decode_content(data or '{}')
        action = headers.get('X-Amz-Target', '').split('.')[-1]

        if action == 'RegisterStreamConsumer':
            consumer = clone(data)
            consumer['ConsumerStatus'] = 'ACTIVE'
            consumer['ConsumerARN'] = '%s/consumer/%s' % (data['StreamARN'], data['ConsumerName'])
            consumer['ConsumerCreationTimestamp'] = float(now_utc())
            consumer = json_safe(consumer)
            STREAM_CONSUMERS.append(consumer)
            return {'Consumer': consumer}
        elif action == 'DeregisterStreamConsumer':
            def consumer_matches(c):
                stream_arn = data.get('StreamARN')
                cons_name = data.get('ConsumerName')
                cons_arn = data.get('ConsumerARN')
                return (c.get('ConsumerARN') == cons_arn or
                    (c.get('StreamARN') == stream_arn and c.get('ConsumerName') == cons_name))
            STREAM_CONSUMERS = [c for c in STREAM_CONSUMERS if not consumer_matches(c)]
            return {}
        elif action == 'ListStreamConsumers':
            result = {
                'Consumers': [c for c in STREAM_CONSUMERS if c.get('StreamARN') == data.get('StreamARN')]
            }
            return result
        elif action == 'DescribeStreamConsumer':
            consumer_arn = data.get('ConsumerARN') or data['ConsumerName']
            consumer_name = data.get('ConsumerName') or data['ConsumerARN']
            creation_timestamp = data.get('ConsumerCreationTimestamp')
            result = {
                'ConsumerDescription': {
                    'ConsumerARN': consumer_arn,
                    'ConsumerCreationTimestamp': creation_timestamp,
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
        data = self.decode_content(data or '{}')
        response._content = self.replace_in_encoded(response.content or '')

        records = []
        if action in (ACTION_CREATE_STREAM, ACTION_DELETE_STREAM):
            event_type = (event_publisher.EVENT_KINESIS_CREATE_STREAM if action == ACTION_CREATE_STREAM
                          else event_publisher.EVENT_KINESIS_DELETE_STREAM)
            payload = {'n': event_publisher.get_hash(data.get('StreamName'))}
            if action == ACTION_CREATE_STREAM:
                payload['s'] = data.get('ShardCount')
            event_publisher.fire_event(event_type, payload=payload)
        elif action == ACTION_PUT_RECORD:
            response_body = self.decode_content(response.content)
            # Note: avoid adding 'encryptionType':'NONE' in the event_record, as this breaks .NET Lambdas
            event_record = {
                'approximateArrivalTimestamp': epoch_timestamp(),
                'data': data['Data'],
                'partitionKey': data['PartitionKey'],
                'sequenceNumber': response_body.get('SequenceNumber')
            }
            event_records = [event_record]
            stream_name = data['StreamName']
            lambda_api.process_kinesis_records(event_records, stream_name)
        elif action == ACTION_PUT_RECORDS:
            event_records = []
            response_body = self.decode_content(response.content)
            if 'Records' in response_body:
                response_records = response_body['Records']
                records = data['Records']
                for index in range(0, len(records)):
                    record = records[index]
                    # Note: avoid adding 'encryptionType':'NONE' in the event_record, as this breaks .NET Lambdas
                    event_record = {
                        'approximateArrivalTimestamp': epoch_timestamp(),
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
        elif action == ACTION_GET_RECORDS:
            sdk_v2 = self.sdk_is_v2(headers.get('User-Agent', '').split(' ')[0])
            results, encoding_type = self.decode_content(response.content, True)

            records = results.get('Records', [])
            if not records:
                return response

            for record in records:
                if sdk_v2:
                    record['ApproximateArrivalTimestamp'] = int(record['ApproximateArrivalTimestamp'] * 1000)
                if not isinstance(record['Data'], str):
                    record['Data'] = base64.encodebytes(bytearray(record['Data']['data']))

            if encoding_type == APPLICATION_CBOR:
                response._content = cbor2.dumps(results)
            else:
                response._content = json.dumps(results)

            return response

    def sdk_is_v2(self, user_agent):
        if re.search(r'\/2.\d+.\d+', user_agent):
            return True
        return False

    def replace_in_encoded(self, data):
        if not data:
            return ''

        decoded, type_encoding = self.decode_content(data, True)

        if type_encoding == APPLICATION_JSON:
            return re.sub(r'arn:aws:kinesis:[^:]+:', 'arn:aws:kinesis:%s:' % aws_stack.get_region(),
            to_str(data))

        if type_encoding == APPLICATION_CBOR:
            replaced = re.sub(r'arn:aws:kinesis:[^:]+:', 'arn:aws:kinesis:%s:' % aws_stack.get_region(),
            json.dumps(decoded))
            return cbor2.dumps(json.loads(replaced))

    def decode_content(self, data, describe=False):
        content_type = ''
        try:
            decoded = json.loads(to_str(data))
            content_type = APPLICATION_JSON
        except UnicodeDecodeError:
            decoded = cbor2.loads(data)
            content_type = APPLICATION_CBOR

        if describe:
            return decoded, content_type

        return decoded


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
