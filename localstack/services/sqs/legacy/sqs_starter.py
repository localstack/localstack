import logging
import types
from html import escape
from typing import Optional

from moto.core.utils import camelcase_to_underscores
from moto.sqs import responses as sqs_responses
from moto.sqs.exceptions import QueueDoesNotExist
from moto.sqs.models import Queue

from localstack import config
from localstack.services.infra import start_moto_server, start_proxy_for_service
from localstack.services.install import SQS_BACKEND_IMPL
from localstack.services.sqs.legacy.elasticmq import ElasticMQSerer
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_free_tcp_port, to_str
from localstack.utils.patch import patch
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)

# backend port (configured at startup)
PORT_SQS_BACKEND = None

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"


# server singleton
_server: Optional[Server] = None


def check_sqs(expect_shutdown=False, print_error=False):
    out = None

    try:
        if not expect_shutdown:
            assert _server, "server has not been started yet"
            assert _server.wait_is_up(5), "gave up waiting for server"

        # check SQS
        endpoint_url = _server.url
        out = aws_stack.connect_to_service(
            service_name="sqs", endpoint_url=endpoint_url
        ).list_queues()
    except Exception:
        if print_error:
            LOG.exception("SQS health check failed")
    if expect_shutdown:
        assert out is None
    else:
        assert out is not None
        assert out.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200


def start_sqs(*args, **kwargs):
    global _server, PORT_SQS_BACKEND

    if _server:
        return _server

    if SQS_BACKEND_IMPL == "elasticmq":
        _server = start_sqs_elasticmq(*args, **kwargs)
    else:
        _server = start_sqs_moto(*args, **kwargs)

    PORT_SQS_BACKEND = _server.port

    return _server


def patch_moto():
    # patch add_message to disable event source mappings in moto
    @patch(Queue.add_message)
    def add_message(fn, self, *args, **kwargs):
        mappings = self.lambda_event_source_mappings
        try:
            # temporarily set mappings to empty dict, to prevent moto from consuming messages from the queue
            self.lambda_event_source_mappings = {}
            return fn(self, *args, **kwargs)
        finally:
            self.lambda_event_source_mappings = mappings

    @patch(Queue._set_attributes)
    def _set_attributes(fn, self, attributes, now=None):
        fn(self, attributes, now)

        integer_fields = ["ReceiveMessageWaitTimeSeconds"]

        for key in integer_fields:
            attribute = camelcase_to_underscores(key)
            setattr(self, attribute, int(getattr(self, attribute, 0)))

    # pass additional globals (e.g., escaping methods) to template render method
    @patch(sqs_responses.SQSResponse.response_template)
    def response_template(fn, self, template_str, *args, **kwargs):
        template = fn(self, template_str, *args, **kwargs)

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

    # escape message responses to allow for special characters like "<"
    sqs_responses.RECEIVE_MESSAGE_RESPONSE = sqs_responses.RECEIVE_MESSAGE_RESPONSE.replace(
        "<StringValue><![CDATA[{{ value.string_value }}]]></StringValue>",
        "<StringValue>{{ _escape(value.string_value) }}</StringValue>",
    )

    # Fix issue with trailing slash
    # https://github.com/localstack/localstack/issues/2874
    @patch(sqs_responses.SQSResponse._get_queue_name, False)
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


def start_sqs_moto(port=None, asynchronous=False, update_listener=None) -> Server:
    from localstack.services import motoserver

    port = port or config.service_port("sqs")
    patch_moto()
    start_moto_server(
        "sqs",
        port,
        name="SQS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )

    return motoserver.get_moto_server()


def start_sqs_elasticmq(port=None, asynchronous=False, update_listener=None) -> Server:
    server = ElasticMQSerer(get_free_tcp_port())
    server.start()
    start_proxy_for_service("sqs", port, server.port, update_listener)
    LOG.debug("waiting for elasticmq server to start...")
    if not server.wait_is_up(120):
        LOG.debug("gave up waiting for elasticmq server after 120 seconds")
    return server
