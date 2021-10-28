import logging

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
        endpoint_url = f"http://127.0.0.1:{swf_listener.PORT_SWF_BACKEND}"
        out = aws_stack.connect_to_service(
            service_name="swf", endpoint_url=endpoint_url
        ).list_domains(registrationStatus="REGISTERED")
    except Exception:
        if print_error:
            LOG.exception("SWF health check failed")
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
