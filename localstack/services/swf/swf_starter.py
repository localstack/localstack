import logging
import traceback

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.services.swf import swf_listener
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_free_tcp_port, wait_for_port_open
from localstack.utils.server import multiserver

LOG = logging.getLogger(__name__)


def check_swf(expect_shutdown=False, print_error=False):
    out = None
    try:
        # wait for port to be opened
        wait_for_port_open(swf_listener.PORT_SWF_BACKEND)
        # check SWF
        out = aws_stack.connect_to_service(service_name="swf").list_domains(
            registrationStatus="REGISTERED"
        )
    except Exception as e:
        if print_error:
            LOG.error("SWF health check failed: %s %s" % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out["domainInfos"], list)


def start_swf(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_SWF
    if not backend_port:
        if config.FORWARD_EDGE_INMEM:
            backend_port = multiserver.get_moto_server_port()
        else:
            backend_port = get_free_tcp_port()
        swf_listener.PORT_SWF_BACKEND = backend_port

    return start_moto_server(
        key="swf",
        name="SWF",
        asynchronous=asynchronous,
        port=port,
        backend_port=backend_port,
        update_listener=update_listener,
    )
