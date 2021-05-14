import json
import logging
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)


class ProxyListenerStepFunctions(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200
        return True

    def return_response(self, method, path, data, headers, response):
        data = json.loads(to_str(data or '{}'))
        name = data.get('name') or (data.get('stateMachineArn') or '').split(':')[-1]
        target = headers.get('X-Amz-Target')

        # publish event
        if target == 'AWSStepFunctions.CreateStateMachine':
            event_publisher.fire_event(event_publisher.EVENT_STEPFUNCTIONS_CREATE_SM,
                payload={'m': event_publisher.get_hash(name)})
        elif target == 'AWSStepFunctions.DeleteStateMachine':
            event_publisher.fire_event(event_publisher.EVENT_STEPFUNCTIONS_DELETE_SM,
                payload={'m': event_publisher.get_hash(name)})


# instantiate listener
UPDATE_STEPFUNCTIONS = ProxyListenerStepFunctions()
