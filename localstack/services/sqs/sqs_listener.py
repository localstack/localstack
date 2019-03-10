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
from localstack.services.generic_proxy import ProxyListener


XMLNS_SQS = 'http://queue.amazonaws.com/doc/2012-11-05/'


SUCCESSFUL_SEND_MESSAGE_XML_TEMPLATE = (
    '<?xml version="1.0"?>'  # noqa: W291
    '<SendMessageResponse xmlns="' + XMLNS_SQS + '">'  # noqa: W291
        '<SendMessageResult>'  # noqa: W291
            '<MD5OfMessageAttributes>{message_attr_hash}</MD5OfMessageAttributes>'  # noqa: W291
            '<MD5OfMessageBody>{message_body_hash}</MD5OfMessageBody>'  # noqa: W291
            '<MessageId>{message_id}</MessageId>'  # noqa: W291
        '</SendMessageResult>'  # noqa: W291
        '<ResponseMetadata>'  # noqa: W291
            '<RequestId>00000000-0000-0000-0000-000000000000</RequestId>'  # noqa: W291
        '</ResponseMetadata>'  # noqa: W291
    '</SendMessageResponse>'  # noqa: W291
)


class ProxyListenerSQS(ProxyListener):

    def forward_request(self, method, path, data, headers):

        if method == 'POST':
            req_data = urlparse.parse_qs(to_str(data))
            if 'QueueName' in req_data:
                encoded_data = urlencode(req_data, doseq=True)
                request = Request(data=encoded_data, headers=headers, method=method)
                return request
            elif req_data.get('Action', [None])[0] == 'SendMessage':
                queue_url = req_data.get('QueueUrl', [path])[0]
                queue_name = queue_url[queue_url.rindex('/') + 1:]
                message_body = req_data.get('MessageBody', [None])[0]
                if lambda_api.process_sqs_message(message_body, queue_name):
                    # If an lambda was listening, do not add the message to the queue
                    new_response = Response()
                    new_response._content = SUCCESSFUL_SEND_MESSAGE_XML_TEMPLATE.format(
                        message_attr_hash=md5(data),
                        message_body_hash=md5(message_body),
                        message_id=str(uuid.uuid4()),
                    )
                    new_response.status_code = 200
                    return new_response

        return True

    def return_response(self, method, path, data, headers, response, request_handler):
        if method == 'OPTIONS' and path == '/':
            # Allow CORS preflight requests to succeed.
            new_response = Response()
            new_response.status_code = 200
            return new_response

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
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

            # patch the response and return the correct endpoint URLs
            if action in ('CreateQueue', 'GetQueueUrl', 'ListQueues'):
                content_str = content_str_original = to_str(response.content)
                new_response = Response()
                new_response.status_code = response.status_code
                new_response.headers = response.headers
                if config.USE_SSL and '<QueueUrl>http://' in content_str:
                    # return https://... if we're supposed to use SSL
                    content_str = re.sub(r'<QueueUrl>\s*http://', r'<QueueUrl>https://', content_str)
                # expose external hostname:port
                external_port = SQS_PORT_EXTERNAL or get_external_port(headers, request_handler)
                content_str = re.sub(r'<QueueUrl>\s*([a-z]+)://[^<]*:([0-9]+)/([^<]*)\s*</QueueUrl>',
                    r'<QueueUrl>\1://%s:%s/\3</QueueUrl>' % (HOSTNAME_EXTERNAL, external_port), content_str)
                new_response._content = content_str
                if content_str_original != new_response._content:
                    # if changes have been made, return patched response
                    new_response.headers['content-length'] = len(new_response._content)
                    return new_response

            # Since the following 2 API calls are not implemented in ElasticMQ, we're mocking them
            # and letting them to return an empty response
            if action == 'TagQueue':
                new_response = Response()
                new_response.status_code = 200
                new_response._content = (
                    '<?xml version="1.0"?>'
                    '<TagQueueResponse>'
                        '<ResponseMetadata>'  # noqa: W291
                            '<RequestId>{}</RequestId>'  # noqa: W291
                        '</ResponseMetadata>'  # noqa: W291
                    '</TagQueueResponse>'
                ).format(uuid.uuid4())
                return new_response
            elif action == 'ListQueueTags':
                new_response = Response()
                new_response.status_code = 200
                new_response._content = (
                    '<?xml version="1.0"?>'
                    '<ListQueueTagsResponse xmlns="{}">'
                        '<ListQueueTagsResult/>'  # noqa: W291
                        '<ResponseMetadata>'  # noqa: W291
                            '<RequestId>{}</RequestId>'  # noqa: W291
                        '</ResponseMetadata>'  # noqa: W291
                    '</ListQueueTagsResponse>'
                ).format(XMLNS_SQS, uuid.uuid4())
                return new_response


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
