import logging
import threading
import time

import pytest
import requests

from localstack.utils.common import get_free_tcp_port, is_port_open, poll_condition
from localstack.utils.net import wait_for_port_closed, wait_for_port_open
from localstack.utils.server.http2_server import run_server

LOG = logging.getLogger(__name__)


class TestHttp2Server:
    def test_run_and_stop_server(self):
        port = get_free_tcp_port()
        host = "127.0.0.1"
        host_2 = "127.0.0.2"

        LOG.info("%.2f starting server on port %d", time.time(), port)
        thread = run_server(port=port, bind_addresses=[host, host_2], asynchronous=True)
        try:
            url = f"http://{host}:{port}"
            url_2 = f"http://{host_2}:{port}"
            assert poll_condition(
                lambda: is_port_open(url, http_path="/"), timeout=15
            ), f"gave up waiting for port {port}"
            assert poll_condition(
                lambda: is_port_open(url_2, http_path="/"), timeout=15
            ), f"gave up waiting for port {port}"
            assert not is_port_open(f"http://127.0.0.3:{port}", http_path="/")
        finally:
            LOG.info("%.2f stopping server on port %d", time.time(), port)
            thread.stop()

        LOG.info("%.2f waiting on server to shut down", time.time())
        thread.join(timeout=15)
        assert not is_port_open(port), "port is still open after stop"
        LOG.info("%.2f port stopped %d", time.time(), port)

    def test_run_and_stop_server_from_different_threads(self):
        port = get_free_tcp_port()
        host = "127.0.0.1"

        LOG.info("%.2f starting server on port %d", time.time(), port)
        thread = run_server(port=port, bind_addresses=[host], asynchronous=True)

        try:
            url = f"http://{host}:{port}"
            assert poll_condition(
                lambda: is_port_open(url, http_path="/"), timeout=15
            ), f"gave up waiting for port {port}"
        finally:
            LOG.info("%.2f stopping server on port %d", time.time(), port)
            threading.Thread(target=thread.stop).start()

        LOG.info("%.2f waiting on server to shut down", time.time())
        thread.join(timeout=15)
        assert not is_port_open(port), "port is still open after stop"
        LOG.info("%.2f port stopped %d", time.time(), port)

    @pytest.mark.parametrize("max_length", [1024 * 1024, 50 * 1024 * 1024])
    def test_max_content_length(self, max_length):
        # start server
        port = get_free_tcp_port()
        host = "127.0.0.1"
        thread = run_server(
            port=port,
            bind_addresses=[host],
            asynchronous=True,
            max_content_length=max_length,
            handler=lambda *args: None,
        )
        wait_for_port_open(port)

        # test successful request
        result = requests.post(f"http://localhost:{port}", data="0" * max_length)
        assert result.status_code == 200
        # test unsuccessful request
        result = requests.post(f"http://localhost:{port}", data="0" * (max_length + 1))
        assert result.status_code == 413  # payload too large

        # clean up
        thread.stop()
        wait_for_port_closed(port)
