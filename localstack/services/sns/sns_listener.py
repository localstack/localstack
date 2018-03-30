import json
import logging
import requests
import uuid
import xmltodict
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_str
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener

# mappings for SNS topic subscriptions
SNS_SUBSCRIPTIONS = {}

# set up logger
LOGGER = logging.getLogger(__name__)


class ProxyListenerSNS(ProxyListener):

    def forward_request(self, method, path, data, headers):

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            req_action = req_data['Action'][0]
            topic_arn = req_data.get('TargetArn') or req_data.get('TopicArn')

            if topic_arn:
                topic_arn = topic_arn[0]
                do_create_topic(topic_arn)

            if req_action == 'SetSubscriptionAttributes':
                sub = get_subscription_by_arn(req_data['SubscriptionArn'][0])
                if not sub:
                    return make_error(message='Unable to find subscription for given ARN', code=400)
                attr_name = req_data['AttributeName'][0]
                attr_value = req_data['AttributeValue'][0]
                sub[attr_name] = attr_value
                return make_response(req_action)
            elif req_action == 'GetSubscriptionAttributes':
                sub = get_subscription_by_arn(req_data['SubscriptionArn'][0])
                if not sub:
                    return make_error(message='Unable to find subscription for given ARN', code=400)
                content = '<Attributes>'
                for key, value in sub.items():
                    content += '<entry><key>%s</key><value>%s</value></entry>\n' % (key, value)
                content += '</Attributes>'
                return make_response(req_action, content=content)
            elif req_action == 'Subscribe':
                if 'Endpoint' not in req_data:
                    return make_error(message='Endpoint not specified in subscription', code=400)
            elif req_action == 'Unsubscribe':
                if 'SubscriptionArn' not in req_data:
                    return make_error(message='SubscriptionArn not specified in unsubscribe request', code=400)
                do_unsubscribe(req_data.get('SubscriptionArn')[0])

            elif req_action == 'Publish':
                message = req_data['Message'][0]
                sqs_client = aws_stack.connect_to_service('sqs')
                for subscriber in SNS_SUBSCRIPTIONS[topic_arn]:
                    filter_policy = json.loads(subscriber.get('FilterPolicy', '{}'))
                    message_attributes = get_message_attributes(req_data)
                    if check_filter_policy(filter_policy, message_attributes):
                        if subscriber['Protocol'] == 'sqs':
                            endpoint = subscriber['Endpoint']
                            if 'sqs_queue_url' in subscriber:
                                queue_url = subscriber.get('sqs_queue_url')
                            elif '://' in endpoint:
                                queue_url = endpoint
                            else:
                                queue_name = endpoint.split(':')[5]
                                queue_url = aws_stack.get_sqs_queue_url(queue_name)
                                subscriber['sqs_queue_url'] = queue_url
                            try:
                                sqs_client.send_message(
                                    QueueUrl=queue_url,
                                    MessageBody=create_sns_message_body(subscriber, req_data)
                                )
                            except Exception as exc:
                                return make_error(message=str(exc), code=400)
                        elif subscriber['Protocol'] == 'lambda':
                            lambda_api.process_sns_notification(
                                subscriber['Endpoint'],
                                topic_arn, message, subject=req_data.get('Subject', [None])[0]
                            )
                        elif subscriber['Protocol'] in ['http', 'https']:
                            try:
                                message_body = create_sns_message_body(subscriber, req_data)
                            except Exception as exc:
                                return make_error(message=str(exc), code=400)
                            requests.post(
                                subscriber['Endpoint'],
                                headers={
                                    'Content-Type': 'text/plain',
                                    'x-amz-sns-message-type': 'Notification'
                                },
                                data=message_body
                            )
                        else:
                            LOGGER.warning('Unexpected protocol "%s" for SNS subscription' % subscriber['Protocol'])
                # return response here because we do not want the request to be forwarded to SNS
                return make_response(req_action)

        return True

    def return_response(self, method, path, data, headers, response):
        # This method is executed by the proxy after we've already received a
        # response from the backend, hence we can utilize the "response" variable here
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            req_action = req_data['Action'][0]
            if req_action == 'Subscribe' and response.status_code < 400:
                response_data = xmltodict.parse(response.content)
                topic_arn = (req_data.get('TargetArn') or req_data.get('TopicArn'))[0]
                sub_arn = response_data['SubscribeResponse']['SubscribeResult']['SubscriptionArn']
                do_subscribe(topic_arn, req_data['Endpoint'][0], req_data['Protocol'][0], sub_arn)


# instantiate listener
UPDATE_SNS = ProxyListenerSNS()


def do_create_topic(topic_arn):
    if topic_arn not in SNS_SUBSCRIPTIONS:
        SNS_SUBSCRIPTIONS[topic_arn] = []


def do_subscribe(topic_arn, endpoint, protocol, subscription_arn):
    subscription = {
        # http://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
        'TopicArn': topic_arn,
        'Endpoint': endpoint,
        'Protocol': protocol,
        'SubscriptionArn': subscription_arn,
        'RawMessageDelivery': 'false'
    }
    SNS_SUBSCRIPTIONS[topic_arn].append(subscription)


def do_unsubscribe(subscription_arn):
    for topic_arn in SNS_SUBSCRIPTIONS:
        SNS_SUBSCRIPTIONS[topic_arn] = [
            sub for sub in SNS_SUBSCRIPTIONS[topic_arn]
            if sub['SubscriptionArn'] != subscription_arn
        ]


# ---------------
# HELPER METHODS
# ---------------

def get_topic_by_arn(topic_arn):
    if topic_arn in SNS_SUBSCRIPTIONS:
        return SNS_SUBSCRIPTIONS[topic_arn]
    else:
        return None


def get_subscription_by_arn(sub_arn):
    # TODO maintain separate map instead of traversing all items
    for key, subscriptions in SNS_SUBSCRIPTIONS.items():
        for sub in subscriptions:
            if sub['SubscriptionArn'] == sub_arn:
                return sub


def make_response(op_name, content=''):
    response = Response()
    if not content:
        content = '<MessageId>%s</MessageId>' % short_uid()
    response._content = """<{op_name}Response xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
        <{op_name}Result>
            {content}
        </{op_name}Result>
        <ResponseMetadata><RequestId>{req_id}</RequestId></ResponseMetadata>
        </{op_name}Response>""".format(op_name=op_name, content=content, req_id=short_uid())
    response.status_code = 200
    return response


def make_error(message, code=400, code_string='InvalidParameter'):
    response = Response()
    response._content = """<ErrorResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/"><Error>
        <Type>Sender</Type>
        <Code>{code_string}</Code>
        <Message>{message}</Message>
        </Error><RequestId>{req_id}</RequestId>
        </ErrorResponse>""".format(message=message, code_string=code_string, req_id=short_uid())
    response.status_code = code
    return response


def create_sns_message_body(subscriber, req_data):
    message = req_data['Message'][0]
    subject = req_data.get('Subject', [None])[0]
    protocol = subscriber['Protocol']

    if subscriber['RawMessageDelivery'] == 'true':
        return message

    if req_data.get('MessageStructure') == ['json']:
        message = json.loads(message)
        try:
            message = message.get(protocol, message['default'])
        except KeyError:
            raise Exception("Unable to find 'default' key in message payload")

    data = {}
    data['MessageId'] = str(uuid.uuid4())
    data['Type'] = 'Notification'
    data['Message'] = message
    data['TopicArn'] = subscriber['TopicArn']
    if subject is not None:
        data['Subject'] = subject
    attributes = get_message_attributes(req_data)
    if attributes:
        data['MessageAttributes'] = attributes
    return json.dumps(data)


def get_message_attributes(req_data):
    attributes = {}
    x = 1
    while True:
        name = req_data.get('MessageAttributes.entry.' + str(x) + '.Name', [None])[0]
        if name is not None:
            attribute = {}
            attribute['Type'] = req_data.get('MessageAttributes.entry.' + str(x) + '.Value.DataType', [None])[0]
            string_value = req_data.get('MessageAttributes.entry.' + str(x) + '.Value.StringValue', [None])[0]
            binary_value = req_data.get('MessageAttributes.entry.' + str(x) + '.Value.BinaryValue', [None])[0]
            if string_value is not None:
                attribute['Value'] = string_value
            elif binary_value is not None:
                attribute['Value'] = binary_value

            attributes[name] = attribute
            x += 1
        else:
            break

    return attributes


def evaluate_numeric_condition(conditions, attribute):
    for i in range(0, len(conditions), 2):
        operator = conditions[i]
        operand = conditions[i + 1]

        if operator == '=':
            if attribute != operand:
                return False
        elif operator == '>':
            if attribute <= operand:
                return False
        elif operator == '<':
            if attribute >= operand:
                return False
        elif operator == '>=':
            if attribute < operand:
                return False
        elif operator == '<=':
            if attribute > operand:
                return False

    return True


def evaluate_filter_policy_conditions(conditions, attribute):
    if type(conditions) is not list:
        conditions = [conditions]

    for condition in conditions:
        if type(condition) is not dict:
            if attribute['Value'] == condition:
                return True
        elif condition.get('anything-but'):
            if attribute['Value'] not in condition.get('anything-but'):
                return True
        elif condition.get('prefix'):
            prefix = condition.get('prefix')
            if attribute['Value'].startswith(prefix):
                return True
        elif condition.get('numeric'):
            if attribute['Type'] == 'Number':
                if evaluate_numeric_condition(condition.get('numeric'), attribute['Value']):
                    return True

    return False


def check_filter_policy(filter_policy, message_attributes):
    if not filter_policy:
        return True

    for criteria in filter_policy:
        conditions = filter_policy.get(criteria)
        attribute = message_attributes.get(criteria)

        if attribute is None:
            return False

        if evaluate_filter_policy_conditions(conditions, attribute) is False:
            return False

    return True
