import xmltodict
from six.moves.urllib import parse as urlparse
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

        return True


# instantiate listener
UPDATE_SQS = ProxyListenerSQS()
