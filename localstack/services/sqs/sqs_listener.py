import re
import uuid
import xmltodict
from six.moves.urllib import parse as urlparse
from six.moves.urllib.parse import urlencode
from requests.models import Request, Response
from localstack import config
from localstack.config import HOSTNAME_EXTERNAL, SQS_PORT_EXTERNAL
from localstack.utils.common import to_str, md5
from localstack.utils.analytics import event_publisher
from localstack.services.awslambda import lambda_api
from localstack.utils.aws.aws_stack import extract_region_from_auth_header
from localstack.services.generic_proxy import ProxyListener


XMLNS_SQS = 'http://queue.amazonaws.com/doc/2012-11-05/'

SUCCESSFUL_SEND_MESSAGE_XML_TEMPLATE = """
    <?xml version="1.0"?>
    <SendMessageResponse xmlns="%s">
        <SendMessageResult>
            <MD5OfMessageAttributes>{message_attr_hash}</MD5OfMessageAttributes>
            <MD5OfMessageBody>{message_body_hash}</MD5OfMessageBody>
            <MessageId>{message_id}</MessageId>
        </SendMessageResult>
        <ResponseMetadata>
            <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
        </ResponseMetadata>
    </SendMessageResponse>
""".strip() % XMLNS_SQS

# list of valid attribute names, and names not supported by the backend (elasticmq)
VALID_ATTRIBUTE_NAMES = ['DelaySeconds', 'MaximumMessageSize', 'MessageRetentionPeriod',
    'Policy', 'ReceiveMessageWaitTimeSeconds', 'RedrivePolicy', 'VisibilityTimeout']
UNSUPPORTED_ATTRIBUTE_NAMES = ['MaximumMessageSize', 'MessageRetentionPeriod', 'Policy', 'RedrivePolicy']

# maps queue URLs to attributes set via the API
QUEUE_ATTRIBUTES = {}


class ProxyListenerSQS(ProxyListener):

    def forward_request(self, method, path, data, headers):
        req_data = self.parse_request_data(method, path, data)

        if req_data:
            action = req_data.get('Action', [None])[0]
            if action == 'SendMessage':
                new_response = self._send_message(path, data, req_data, headers)
                if new_response:
                    return new_response
            elif action == 'SetQueueAttributes':
                self._set_queue_attributes(req_data)

            if 'QueueName' in req_data:
                encoded_data = urlencode(req_data, doseq=True) if method == 'POST' else ''
                modified_url = None
                if method == 'GET':
                    base_path = path.partition('?')[0]
                    modified_url = '%s?%s' % (base_path, urlencode(req_data, doseq=True))
                request = Request(data=encoded_data, url=modified_url, headers=headers, method=method)
                return request

        return True

    def parse_request_data(self, method, path, data):
        """ Extract request data either from query string (for GET) or request body (for POST). """
        if method == 'POST':
            return urlparse.parse_qs(to_str(data))
        elif method == 'GET':
            parsed_path = urlparse.urlparse(path)
            return urlparse.parse_qs(parsed_path.query)
        return {}

    def return_response(self, method, path, data, headers, response, request_handler):
        if method == 'OPTIONS' and path == '/':
            # Allow CORS preflight requests to succeed.
            return 200

        if method == 'POST' and path == '/':
            region_name = extract_region_from_auth_header(headers)
            req_data = urlparse.parse_qs(to_str(data))
            action = req_data.get('Action', [None])[0]
            content_str = content_str_original = to_str(response.content)

            self._fire_event(req_data, response)

            # patch the response and add missing attributes
            if action == 'GetQueueAttributes':
                content_str = self._add_queue_attributes(req_data, content_str)

            # patch the response and return the correct endpoint URLs / ARNs
            if action in ('CreateQueue', 'GetQueueUrl', 'ListQueues', 'GetQueueAttributes'):
                if config.USE_SSL and '<QueueUrl>http://' in content_str:
                    # return https://... if we're supposed to use SSL
                    content_str = re.sub(r'<QueueUrl>\s*http://', r'<QueueUrl>https://', content_str)
                # expose external hostname:port
                external_port = SQS_PORT_EXTERNAL or get_external_port(headers, request_handler)
                content_str = re.sub(r'<QueueUrl>\s*([a-z]+)://[^<]*:([0-9]+)/([^<]*)\s*</QueueUrl>',
                    r'<QueueUrl>\1://%s:%s/\3</QueueUrl>' % (HOSTNAME_EXTERNAL, external_port), content_str)
                # fix queue ARN
                content_str = re.sub(r'<([a-zA-Z0-9]+)>\s*arn:aws:sqs:elasticmq:([^<]+)</([a-zA-Z0-9]+)>',
                    r'<\1>arn:aws:sqs:%s:\2</\3>' % (region_name), content_str)

            if content_str_original != content_str:
                # if changes have been made, return patched response
                new_response = Response()
                new_response.status_code = response.status_code
                new_response.headers = response.headers
                new_response._content = content_str
                new_response.headers['content-length'] = len(new_response._content)
                return new_response

            # Since the following 2 API calls are not implemented in ElasticMQ, we're mocking them
            # and letting them to return an empty response
            if action == 'TagQueue':
                new_response = Response()
                new_response.status_code = 200
                new_response._content = ("""
                    <?xml version="1.0"?>
                    <TagQueueResponse>
                        <ResponseMetadata>
                            <RequestId>{}</RequestId>
                        </ResponseMetadata>
                    </TagQueueResponse>
                """).strip().format(uuid.uuid4())
                return new_response
            elif action == 'ListQueueTags':
                new_response = Response()
                new_response.status_code = 200
                new_response._content = ("""
                    <?xml version="1.0"?>
                    <ListQueueTagsResponse xmlns="{}">
                        <ListQueueTagsResult/>
                        <ResponseMetadata>
                            <RequestId>{}</RequestId>
                        </ResponseMetadata>
                    </ListQueueTagsResponse>
                """).strip().format(XMLNS_SQS, uuid.uuid4())
                return new_response

    # Format of the message Name attribute is MessageAttribute.<int id>.<field>
    # Format of the Value attributes is MessageAttribute.<int id>.Value.DataType
    # and MessageAttribute.<int id>.Value.<Type>Value
    #
    # The data schema changes on transfer between SQS and Lambda (at least)
    # JS functions in real AWS!
    # It is unknown at this time whether this data structure change affects different
    # languages in different ways.
    #
    # The MessageAttributes specified in the SQS payload (in JavaScript):
    # var params = {
    #   MessageBody: "body string",
    #   MessageAttributes: {
    #       "attr_1": {
    #           DataType: "String",
    #           StringValue: "attr_1_value"
    #       },
    #       "attr_2": {
    #           DataType: "String",
    #           StringValue: "attr_2_value"
    #       }
    #   }
    # }
    #
    # The MessageAttributes specified above are massaged into the following structure:
    # {
    #    attr_1: {
    #      stringValue: 'attr_1_value',
    #      stringListValues: [],
    #      binaryListValues: [],
    #      dataType: 'String'
    #    },
    #    attr_2: {
    #      stringValue: 'attr_2_value',
    #      stringListValues: [],
    #      binaryListValues: [],
    #      dataType: 'String'
    #    }
    # }
    def format_message_attributes(self, data):
        prefix = 'MessageAttribute'
        names = []
        for (k, name) in [(k, data[k]) for k in data if k.startswith(prefix) and k.endswith('.Name')]:
            attr_name = name[0]
            k_id = k.split('.')[1]
            names.append((attr_name, k_id))

        msg_attrs = {}
        for (key_name, key_id) in names:
            msg_attrs[key_name] = {}
            # Find vals for each key_id
            attrs = [(k, data[k]) for k in data
                if k.startswith('{}.{}.'.format(prefix, key_id)) and not k.endswith('.Name')]
            for (attr_k, attr_v) in attrs:
                attr_name = attr_k.split('.')[3]
                msg_attrs[key_name][attr_name[0].lower() + attr_name[1:]] = attr_v[0]

            # These fields are set in the payload sent to Lambda.
            # It is extremely likely additional work will
            # be required to support these fields
            msg_attrs[key_name]['stringListValues'] = []
            msg_attrs[key_name]['binaryListValues'] = []

        return msg_attrs

    # Format attributes as dict. Example input:
    #  {
    #    'Attribute.1.Name': ['Policy'],
    #    'Attribute.1.Value': ['...']
    #  }
    def _format_attributes(self, req_data):
        result = {}
        for i in range(1, 500):
            key1 = 'Attribute.%s.Name' % i
            key2 = 'Attribute.%s.Value' % i
            if key1 not in req_data:
                break
            key_name = req_data[key1][0]
            key_value = req_data[key2][0]
            result[key_name] = key_value
        return result

    def _send_message(self, path, data, req_data, headers):
        queue_url = req_data.get('QueueUrl', [path.partition('?')[0]])[0]
        queue_name = queue_url[queue_url.rindex('/') + 1:]
        message_body = req_data.get('MessageBody', [None])[0]
        message_attributes = self.format_message_attributes(req_data)
        region_name = extract_region_from_auth_header(headers)

        process_result = lambda_api.process_sqs_message(message_body,
            message_attributes, queue_name, region_name=region_name)
        if process_result:
            # If a Lambda was listening, do not add the message to the queue
            new_response = Response()
            new_response._content = SUCCESSFUL_SEND_MESSAGE_XML_TEMPLATE.format(
                message_attr_hash=md5(data),
                message_body_hash=md5(message_body),
                message_id=str(uuid.uuid4())
            )
            new_response.status_code = 200
            return new_response

    def _set_queue_attributes(self, req_data):
        queue_url = req_data['QueueUrl'][0]
        attrs = self._format_attributes(req_data)
        # select only the attributes in UNSUPPORTED_ATTRIBUTE_NAMES
        attrs = dict([(k, v) for k, v in attrs.items() if k in UNSUPPORTED_ATTRIBUTE_NAMES])
        QUEUE_ATTRIBUTES[queue_url] = QUEUE_ATTRIBUTES.get(queue_url) or {}
        QUEUE_ATTRIBUTES[queue_url].update(attrs)

    def _add_queue_attributes(self, req_data, content_str):
        flags = re.MULTILINE | re.DOTALL
        queue_url = req_data['QueueUrl'][0]
        regex = r'(.*<GetQueueAttributesResult>)(.*)(</GetQueueAttributesResult>.*)'
        attrs = re.sub(regex, r'\2', content_str, flags=flags)
        for key, value in QUEUE_ATTRIBUTES.get(queue_url, {}).items():
            if not re.match(r'<Name>\s*%s\s*</Name>' % key, attrs, flags=flags):
                attrs += '<Attribute><Name>%s</Name><Value>%s</Value></Attribute>' % (key, value)
        content_str = (re.sub(regex, r'\1', content_str, flags=flags) +
            attrs + re.sub(regex, r'\3', content_str, flags=flags))
        return content_str

    def _fire_event(self, req_data, response):
        action = req_data.get('Action', [None])[0]
        event_type = None
        queue_url = None
        if action == 'CreateQueue':
            event_type = event_publisher.EVENT_SQS_CREATE_QUEUE
            response_data = xmltodict.parse(response.content)
            if 'CreateQueueResponse' in response_data:
                queue_url = response_data['CreateQueueResponse']['CreateQueueResult']['QueueUrl']
        elif action == 'DeleteQueue':
            event_type = event_publisher.EVENT_SQS_DELETE_QUEUE
            queue_url = req_data.get('QueueUrl', [None])[0]

        if event_type and queue_url:
            event_publisher.fire_event(event_type, payload={'u': event_publisher.get_hash(queue_url)})


# extract the external port used by the client to make the request
def get_external_port(headers, request_handler):
    host = headers.get('Host', '')
    if ':' in host:
        return int(host.split(':')[1])
    # If we cannot find the Host header, then fall back to the port of the proxy.
    # (note that this could be incorrect, e.g., if running in Docker with a host port that
    # is different from the internal container port, but there is not much else we can do.)
    return request_handler.proxy.port


# instantiate listener
UPDATE_SQS = ProxyListenerSQS()
