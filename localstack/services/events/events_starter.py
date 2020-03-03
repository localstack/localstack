import json
import sys
from moto.events.responses import EventsHandler
from moto.server import main as moto_main
from localstack import config
from localstack.constants import DEFAULT_PORT_EVENTS_BACKEND
from localstack.utils.common import FuncThread
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run
)


RUN_SERVER_IN_PROCESS = False


def start_events(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_EVENTS
    backend_port = DEFAULT_PORT_EVENTS_BACKEND

    print('Starting mock Cloudwatch Events (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('events', port, backend_port, update_listener)

    if RUN_SERVER_IN_PROCESS:
        cmd = 'python "%s" events -p %s -H 0.0.0.0' % (__file__, backend_port)
        env_vars = {'PYTHONPATH': ':'.join(sys.path)}
        return do_run(cmd, asynchronous, env_vars=env_vars)
    else:
        argv = ['events', '-p', str(backend_port), '-H', '0.0.0.0']
        thread = FuncThread(start_up, argv)
        thread.start()
        return thread


def apply_patches():
    # Patch _put_targets  #2101
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


def start_up(*args):
    # patch moto implementation
    apply_patches()

    return moto_main(*args)
