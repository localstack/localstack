import re
import xmltodict
from six.moves.urllib import parse as urlparse
from requests.models import Response
from localstack import config
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerSQS(ProxyListener):

    def return_response(self, method, path, data, headers, response):

        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
            action = req_data.get('Action', [None])[0]
            event_type = None
            if action == 'CreateQueue':
                event_type = event_publisher.EVENT_SQS_CREATE_QUEUE
                response_data = xmltodict.parse(response.content)
                queue_url = response_data['CreateQueueResponse']['CreateQueueResult']['QueueUrl']
            elif action == 'DeleteQueue':
                event_type = event_publisher.EVENT_SQS_DELETE_QUEUE
                queue_url = req_data.get('QueueUrl', [None])[0]

            if event_type:
                event_publisher.fire_event(event_type, payload={'u': event_publisher.get_hash(queue_url)})

            # patch the response and return https://... if we're supposed to use SSL
            if config.USE_SSL and action in ('CreateQueue', 'GetQueueUrl'):
                content_str = to_str(response.content)
                if '<QueueUrl>http://' in content_str:
                    new_response = Response()
                    new_response.status_code = response.status_code
                    new_response.headers = response.headers
                    new_response._content = re.sub(r'<QueueUrl>\s*http://', '<QueueUrl>https://', content_str)
                    new_response.headers['content-length'] = len(new_response._content)
                    return new_response


# instantiate listener
UPDATE_SQS = ProxyListenerSQS()
