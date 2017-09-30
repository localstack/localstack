import re
import xmltodict
from six.moves.urllib import parse as urlparse
from six.moves.urllib.parse import urlencode
from requests.models import Request, Response
from localstack import config
from localstack.config import HOSTNAME_EXTERNAL
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerSQS(ProxyListener):

    def forward_request(self, method, path, data, headers):

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
            if 'QueueName' in req_data:
                if '.' in req_data['QueueName'][0]:
                    # ElasticMQ currently does not support "." in the queue name, e.g., for *.fifo queues
                    # TODO: remove this once *.fifo queues are supported in ElasticMQ
                    req_data['QueueName'][0] = req_data['QueueName'][0].replace('.', '_')
                    modified_data = urlencode(req_data, doseq=True)
                    request = Request(data=modified_data, headers=headers, method=method)
                    return request

        return True

    def return_response(self, method, path, data, headers, response):

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
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
                # expose external hostname
                content_str = re.sub(r'<QueueUrl>\s*([a-z]+)://[^<]*:([0-9]+)/([^<]*)\s*</QueueUrl>',
                    r'<QueueUrl>\1://%s:\2/\3</QueueUrl>' % HOSTNAME_EXTERNAL, content_str)
                new_response._content = content_str
                if content_str_original != new_response._content:
                    # if changes have been made, return patched response
                    new_response.headers['content-length'] = len(new_response._content)
                    return new_response


# instantiate listener
UPDATE_SQS = ProxyListenerSQS()
