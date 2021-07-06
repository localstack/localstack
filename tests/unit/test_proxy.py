import logging
import unittest

from localstack_ext.bootstrap.local_daemon import get_free_tcp_port

from localstack import config
from localstack.services.infra import start_proxy_for_service
from localstack.utils.common import is_port_open, poll_condition

LOG = logging.getLogger(__name__)


class TestProxyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cfg_val = config.FORWARD_EDGE_INMEM
        config.FORWARD_EDGE_INMEM = False

    @classmethod
    def tearDownClass(cls) -> None:
        config.FORWARD_EDGE_INMEM = cls.cfg_val

    def test_start_and_stop(self):
        proxy_port = get_free_tcp_port()
        backend_port = get_free_tcp_port()

        server = start_proxy_for_service(
            "myservice",
            proxy_port,
            backend_port,
            update_listener=None,
            quiet=True,
            params={"protocol_version": "HTTP/1.0"},
        )

        self.assertIsNotNone(server)

        try:
            self.assertTrue(
                poll_condition(lambda: is_port_open(proxy_port), timeout=15),
                "gave up waiting for port %d" % proxy_port,
            )
        finally:
            print("stopping proxy server")
            server.stop()

        print("waiting max 15 seconds for server to terminate")
        server.join(timeout=15)

        self.assertFalse(is_port_open(proxy_port))
