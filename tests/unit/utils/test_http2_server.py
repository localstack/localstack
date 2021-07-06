import logging
import threading
import time
import unittest

from localstack.utils.common import get_free_tcp_port, is_port_open, poll_condition
from localstack.utils.server.http2_server import run_server

LOG = logging.getLogger(__name__)


class TestHttp2Server(unittest.TestCase):
    def test_run_and_stop_server(self):
        port = get_free_tcp_port()
        host = "127.0.0.1"

        LOG.info("%.2f starting server on port %d", time.time(), port)
        thread = run_server(port=port, bind_address=host, asynchronous=True)
        try:
            url = f"http://{host}:{port}"
            self.assertTrue(
                poll_condition(lambda: is_port_open(url, http_path="/"), timeout=15),
                "gave up waiting for port %d " % port,
            )
        finally:
            LOG.info("%.2f stopping server on port %d", time.time(), port)
            thread.stop()

        LOG.info("%.2f waiting on server to shut down", time.time())
        thread.join(timeout=15)
        self.assertFalse(is_port_open(port), "port is still open after stop")
        LOG.info("%.2f port stopped %d", time.time(), port)

    def test_run_and_stop_server_from_different_threads(self):
        port = get_free_tcp_port()
        host = "127.0.0.1"

        LOG.info("%.2f starting server on port %d", time.time(), port)
        thread = run_server(port=port, bind_address=host, asynchronous=True)

        try:
            url = f"http://{host}:{port}"
            self.assertTrue(
                poll_condition(lambda: is_port_open(url, http_path="/"), timeout=15),
                "gave up waiting for port %d " % port,
            )
        finally:
            LOG.info("%.2f stopping server on port %d", time.time(), port)
            threading.Thread(target=thread.stop).start()

        LOG.info("%.2f waiting on server to shut down", time.time())
        thread.join(timeout=15)
        self.assertFalse(is_port_open(port), "port is still open after stop")
        LOG.info("%.2f port stopped %d", time.time(), port)
