import re
import uuid
import xmltodict
from six.moves.urllib import parse as urlparse
from six.moves.urllib.parse import urlencode
from requests.models import Request, Response
from localstack import config
from localstack.config import HOSTNAME_EXTERNAL
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener


XMLNS_SQS = 'http://queue.amazonaws.com/doc/2012-11-05/'


class ProxyListenerSQS(ProxyListener):

    def forward_request(self, method, path, data, headers):

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            if 'QueueName' in req_data:
                if '.' in req_data['QueueName'][0]:
                    # ElasticMQ currently does not support "." in the queue name, e.g., for *.fifo queues
                    # TODO: remove this once *.fifo queues are supported in ElasticMQ
                    req_data['QueueName'][0] = req_data['QueueName'][0].replace('.', '_')
                    modified_data = urlencode(req_data, doseq=True)
                    request = Request(data=modified_data, headers=headers, method=method)
                    return request

        return True

    def return_response(self, method, path, data, headers, response, request_handler):

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
                external_port = get_external_port(headers, request_handler)
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
