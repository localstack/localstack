import re
import json
import time
import base64
import random
import cbor2
from requests.models import Response
from localstack import config
from localstack.constants import APPLICATION_JSON, APPLICATION_CBOR
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, json_safe, clone, epoch_timestamp, now_utc
from localstack.utils.analytics import event_publisher
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import convert_to_binary_event_payload

# action headers (should be left here - imported/required by other files)
ACTION_PREFIX = 'Kinesis_20131202'
ACTION_PUT_RECORD = '%s.PutRecord' % ACTION_PREFIX
ACTION_PUT_RECORDS = '%s.PutRecords' % ACTION_PREFIX
ACTION_LIST_STREAMS = '%s.ListStreams' % ACTION_PREFIX

# list of stream consumer details
STREAM_CONSUMERS = []


class ProxyListenerKinesis(ProxyListener):

    def forward_request(self, method, path, data, headers):
        global STREAM_CONSUMERS
        data, encoding_type = self.decode_content(data or '{}', True)
        action = headers.get('X-Amz-Target', '').split('.')[-1]
        if action == 'RegisterStreamConsumer':
            prev_consumer = find_consumer(data.get('ConsumerARN', ''),
                data.get('ConsumerName', ''), data.get('StreamARN', ''))

            if prev_consumer:
                msg = 'Consumer %s already exists' % prev_consumer.get('ConsumerARN')
                return simple_error_response(msg, 400, 'ResourceAlreadyExists', encoding_type)

            consumer = clone(data)
            consumer['ConsumerStatus'] = 'ACTIVE'
            consumer['ConsumerARN'] = '%s/consumer/%s' % (data['StreamARN'], data['ConsumerName'])
            consumer['ConsumerCreationTimestamp'] = now_utc()
            consumer = json_safe(consumer)
            STREAM_CONSUMERS.append(consumer)

            result = {'Consumer': consumer}

            return encoded_response(result, encoding_type)

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
            return encoded_response(result, encoding_type)

        elif action == 'DescribeStreamConsumer':
            consumer_arn = data.get('ConsumerARN', '')
            consumer_name = data.get('ConsumerName', '')
            stream_arn = data.get('StreamArn', '')

            consumer_to_locate = find_consumer(consumer_arn, consumer_name, stream_arn)
            if(not consumer_to_locate):
                error_msg = 'Consumer %s not found.' % (consumer_arn or consumer_name)
                return simple_error_response(error_msg, 400, 'ResourceNotFoundException', encoding_type)

            creation_timestamp = consumer_to_locate.get('ConsumerCreationTimestamp')
            time_formated = int(creation_timestamp) if encoding_type is not APPLICATION_JSON else creation_timestamp

            result = {
                'ConsumerDescription': {
                    'ConsumerARN': consumer_to_locate.get('ConsumerArn'),
                    'ConsumerCreationTimestamp': time_formated,
                    'ConsumerName': consumer_to_locate.get('ConsumerName'),
                    'ConsumerStatus': 'ACTIVE',
                    'StreamARN': data.get('StreamARN')
                }
            }

            return encoded_response(result, encoding_type)

        elif action == 'SubscribeToShard':
            result = subscribe_to_shard(data, headers)
            return result

        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            if action in ['PutRecord', 'PutRecords']:
                return kinesis_error_response(data, action)

        return True

    def return_response(self, method, path, data, headers, response):
        action = headers.get('X-Amz-Target', '').split('.')[-1]
        data, encoding_type = self.decode_content(data or '{}', True)
        response._content = self.replace_in_encoded(response.content or '')
        records = []
        if action in ('CreateStream', 'DeleteStream'):
            event_type = (event_publisher.EVENT_KINESIS_CREATE_STREAM if action == 'CreateStream'
                          else event_publisher.EVENT_KINESIS_DELETE_STREAM)
            payload = {'n': event_publisher.get_hash(data.get('StreamName'))}
            if action == 'CreateStream':
                payload['s'] = data.get('ShardCount')
            event_publisher.fire_event(event_type, payload=payload)
        elif action == 'PutRecord':
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
        elif action == 'PutRecords':
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
        elif action == 'UpdateShardCount':
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
        elif action == 'GetRecords':
            sdk_v2 = self.sdk_is_v2(headers.get('User-Agent', '').split(' ')[0])
            results, encoding_type = self.decode_content(response.content, True)

            records = results.get('Records', [])
            if not records:
                return response

            for record in records:
                if sdk_v2:
                    record['ApproximateArrivalTimestamp'] = int(record['ApproximateArrivalTimestamp'])
                if not isinstance(record['Data'], str):
                    # Remove double quotes from data written as bytes
                    # https://github.com/localstack/localstack/issues/3588
                    tmp = bytearray(record['Data']['data'])
                    if len(tmp) >= 2 and tmp[0] == tmp[-1] == b'"'[0]:
                        record['Data'] = tmp[1:-1]
                else:
                    tmp = base64.b64decode(record['Data'])
                    if len(tmp) >= 2 and tmp[0] == tmp[-1] == b'"'[0]:
                        tmp = tmp[1:-1]

                record['Data'] = to_str(base64.b64encode(tmp))

            response._content = cbor2.dumps(results) if encoding_type == APPLICATION_CBOR else json.dumps(results)
            return response

    def sdk_is_v2(self, user_agent):
        if re.search(r'\/2.\d+.\d+', user_agent):
            return True
        return False

    def replace_in_encoded(self, data):
        if not data:
            return ''

        def _replace(_data):
            return re.sub(r'arn:aws:kinesis:[^:]+:', 'arn:aws:kinesis:%s:' % aws_stack.get_region(), _data)
        decoded, type_encoding = self.decode_content(data, True)

        if type_encoding == APPLICATION_JSON:
            return _replace(to_str(data))

        if type_encoding == APPLICATION_CBOR:
            replaced = _replace(json.dumps(decoded))
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


def encode_data(data, encoding_type):
    if encoding_type == APPLICATION_CBOR:
        return cbor2.dumps(data)
    return json.dumps(data)


def encoded_response(data, encoding_type=APPLICATION_JSON, status_code=200):
    response = Response()
    response.status_code = status_code
    response.headers.update({'content-type': encoding_type})
    response._content = encode_data(data, encoding_type)
    return response


def subscribe_to_shard(data, headers):
    kinesis = aws_stack.connect_to_service('kinesis')
    stream_name = find_stream_for_consumer(data['ConsumerARN'])
    iter_type = data['StartingPosition']['Type']
    iterator = kinesis.get_shard_iterator(StreamName=stream_name,
        ShardId=data['ShardId'], ShardIteratorType=iter_type)['ShardIterator']
    data_needs_encoding = False
    if 'java' in headers.get('User-Agent', '').split(' ')[0]:
        data_needs_encoding = True

    def send_events():
        yield convert_to_binary_event_payload('', event_type='initial-response')
        iter = iterator
        # TODO: find better way to run loop up to max 5 minutes (until connection terminates)!
        for i in range(5 * 60):
            result = kinesis.get_records(ShardIterator=iter)
            iter = result.get('NextShardIterator')
            records = result.get('Records', [])
            for record in records:
                record['ApproximateArrivalTimestamp'] = record['ApproximateArrivalTimestamp'].timestamp()
                if data_needs_encoding:
                    record['Data'] = base64.b64encode(record['Data'])
                record['Data'] = to_str(record['Data'])
            if not records:
                time.sleep(1)
                continue

            result = json.dumps({'Records': json_safe(records)})
            yield convert_to_binary_event_payload(result, event_type='SubscribeToShardEvent')

    headers = {}
    return send_events(), headers


def find_consumer(consumer_arn='', consumer_name='', stream_arn=''):
    for consumer in STREAM_CONSUMERS:
        if consumer_arn and consumer_arn == consumer.get('ConsumerARN'):
            return consumer
        elif consumer_name == consumer.get('ConsumerName') and stream_arn == consumer.get('StreamArn'):
            return consumer


def find_stream_for_consumer(consumer_arn):
    kinesis = aws_stack.connect_to_service('kinesis')
    for stream_name in kinesis.list_streams()['StreamNames']:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        for cons in kinesis.list_stream_consumers(StreamARN=stream_arn)['Consumers']:
            if cons['ConsumerARN'] == consumer_arn:
                return stream_name
    raise Exception('Unable to find stream for stream consumer %s' % consumer_arn)


def simple_error_response(msg, code, type_error, encoding_type=APPLICATION_JSON):
    body = {'message': msg,
        '__type': type_error}
    return encoded_response(body, encoding_type, code)


def kinesis_error_response(data, action):
    error_response = Response()

    if action == 'PutRecord':
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


# instantiate listener
UPDATE_KINESIS = ProxyListenerKinesis()
