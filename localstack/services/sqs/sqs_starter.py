import logging
import os
import types
from html import escape

from moto.core.utils import camelcase_to_underscores
from moto.sqs import responses as sqs_responses
from moto.sqs.exceptions import QueueDoesNotExist
from moto.sqs.models import Queue

from localstack import config
from localstack.config import LOCALSTACK_HOSTNAME, TMP_FOLDER
from localstack.services.infra import (
    do_run,
    log_startup_message,
    start_moto_server,
    start_proxy_for_service,
)
from localstack.services.install import INSTALL_DIR_ELASTICMQ, SQS_BACKEND_IMPL, install_elasticmq
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    TMP_FILES,
    get_free_tcp_port,
    save_file,
    short_uid,
    to_str,
    wait_for_port_open,
)

LOG = logging.getLogger(__name__)

# backend port (configured at startup)
PORT_SQS_BACKEND = None

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"


def check_sqs(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(PORT_SQS_BACKEND)
        # check SQS
        endpoint_url = f"http://127.0.0.1:{PORT_SQS_BACKEND}"
        out = aws_stack.connect_to_service(
            service_name="sqs", endpoint_url=endpoint_url
        ).list_queues()
    except Exception:
        if print_error:
            LOG.exception("SQS health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200


def start_sqs(*args, **kwargs):
    if SQS_BACKEND_IMPL == "moto":
        return start_sqs_moto(*args, **kwargs)
    return start_sqs_elasticmq(*args, **kwargs)


def patch_moto():
    # patch add_message to disable event source mappings in moto
    def add_message(self, *args, **kwargs):
        mappings = self.lambda_event_source_mappings
        try:
            # temporarily set mappings to empty dict, to prevent moto from consuming messages from the queue
            self.lambda_event_source_mappings = {}
            return add_message_orig(self, *args, **kwargs)
        finally:
            self.lambda_event_source_mappings = mappings

    add_message_orig = Queue.add_message
    Queue.add_message = add_message

    _set_attributes_orig = Queue._set_attributes

    def _set_attributes(self, attributes, now=None):
        _set_attributes_orig(self, attributes, now)

        integer_fields = ["ReceiveMessageWaitTimeSeconds"]

        for key in integer_fields:
            attribute = camelcase_to_underscores(key)
            setattr(self, attribute, int(getattr(self, attribute, 0)))

    Queue._set_attributes = _set_attributes

    # pass additional globals (e.g., escaping methods) to template render method
    def response_template(self, template_str, *args, **kwargs):
        template = response_template_orig(self, template_str, *args, **kwargs)

        def _escape(val):
            try:
                return val and escape(to_str(val))
            except Exception:
                return val

        def render(self, *args, **kwargs):
            return render_orig(*args, _escape=_escape, **kwargs)

        if not hasattr(template, "__patched"):
            render_orig = template.render
            template.render = types.MethodType(render, template)
            template.__patched = True
        return template

    response_template_orig = sqs_responses.SQSResponse.response_template
    sqs_responses.SQSResponse.response_template = response_template

    # escape message responses to allow for special characters like "<"
    sqs_responses.RECEIVE_MESSAGE_RESPONSE = sqs_responses.RECEIVE_MESSAGE_RESPONSE.replace(
        "<StringValue>{{ value.string_value }}</StringValue>",
        "<StringValue>{{ _escape(value.string_value) }}</StringValue>",
    )

    # Fix issue with trailing slash
    # https://github.com/localstack/localstack/issues/2874
    def sqs_responses_get_queue_name(self):
        try:
            queue_url = self.querystring.get("QueueUrl")[0]
            queue_name_data = queue_url.split("/")[4:]
            queue_name_data = [queue_attr for queue_attr in queue_name_data if queue_attr]
            queue_name = "/".join(queue_name_data)
        except TypeError:
            # Fallback to reading from the URL
            queue_name = self.path.split("/")[2]

        if not queue_name:
            raise QueueDoesNotExist()

        return queue_name

    sqs_responses.SQSResponse._get_queue_name = sqs_responses_get_queue_name


def start_sqs_moto(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SQS
    patch_moto()
    result = start_moto_server(
        "sqs",
        port,
        name="SQS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
    global PORT_SQS_BACKEND
    PORT_SQS_BACKEND = result.service_port
    return result


def start_sqs_elasticmq(port=None, asynchronous=False, update_listener=None):
    global PORT_SQS_BACKEND

    port = port or config.PORT_SQS
    install_elasticmq()
    PORT_SQS_BACKEND = get_free_tcp_port()
    # create config file
    config_params = """
    include classpath("application.conf")
    node-address {
        protocol = http
        host = "%s"
        port = %s
        context-path = ""
    }
    rest-sqs {
        enabled = true
        bind-port = %s
        bind-hostname = "0.0.0.0"
        sqs-limits = strict
    }
    """ % (
        LOCALSTACK_HOSTNAME,
        port,
        PORT_SQS_BACKEND,
    )
    config_file = os.path.join(TMP_FOLDER, "sqs.%s.conf" % short_uid())
    TMP_FILES.append(config_file)
    save_file(config_file, config_params)
    # start process
    cmd = "java -Dconfig.file=%s -Xmx%s -jar %s/elasticmq-server.jar" % (
        config_file,
        MAX_HEAP_SIZE,
        INSTALL_DIR_ELASTICMQ,
    )
    log_startup_message("SQS")
    start_proxy_for_service("sqs", port, PORT_SQS_BACKEND, update_listener)
    return do_run(cmd, asynchronous)
