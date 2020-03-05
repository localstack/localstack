import json
from moto.events.responses import EventsHandler
from localstack import config
from localstack.constants import DEFAULT_PORT_EVENTS_BACKEND
from localstack.services.infra import start_moto_server


def start_events(port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_EVENTS
    backend_port = DEFAULT_PORT_EVENTS_BACKEND

    apply_patches()

    return start_moto_server(
        key='events',
        port=port,
        name='Cloudwatch Events',
        asynchronous=asynchronous,
        backend_port=backend_port,
        update_listener=update_listener
    )


def apply_patches():
    # Patch _put_targets  #2101 Events put-targets does not respond
    def EventsHandler_put_targets(self):
        rule_name = self._get_param('Rule')
        targets = self._get_param('Targets')

        if not rule_name:
            return self.error('ValidationException', 'Parameter Rule is required.')

        if not targets:
            return self.error('ValidationException', 'Parameter Targets is required.')

        if not self.events_backend.put_targets(rule_name, targets):
            return self.error(
                'ResourceNotFoundException', 'Rule ' + rule_name + ' does not exist.'
            )

        return json.dumps({'FailedEntryCount': 0, 'FailedEntries': []}), self.response_headers

    EventsHandler.put_targets = EventsHandler_put_targets
