import socket
import threading
from threading import Thread

import pytest

from localstack.utils.net import get_free_tcp_port, is_port_open
from localstack.utils.server.tcp_proxy import TCPProxy


class TestTCPProxy:
    @pytest.fixture
    def tcp_proxy(self):
        proxies: list[TCPProxy] = []

        def _create_proxy(target_address: str, target_port: int) -> TCPProxy:
            port = get_free_tcp_port()
            proxy = TCPProxy(
                target_address=target_address, target_port=target_port, port=port, host="127.0.0.1"
            )
            proxies.append(proxy)
            return proxy

        yield _create_proxy

        for proxy in proxies:
            proxy.shutdown()

    @pytest.fixture
    def tcp_echo_server_port(self):
        """Single threaded TCP echo server"""
        stopped = threading.Event()
        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_sock.bind(("127.0.0.1", 0))
        port = s_sock.getsockname()[1]

        def _run_echo_server():
            with s_sock:
                s_sock.listen(1)
                while not stopped.is_set():
                    try:
                        conn, _ = s_sock.accept()
                    except OSError:
                        # this happens when we shut down the server socket
                        pass
                    with conn:
                        while not stopped.is_set():
                            data = conn.recv(1024)
                            if not data:
                                break
                            conn.sendall(data)

        echo_server_thread = Thread(target=_run_echo_server)
        echo_server_thread.start()

        yield port

        stopped.set()
        s_sock.shutdown(socket.SHUT_RDWR)
        s_sock.close()
        echo_server_thread.join(5)
        assert not echo_server_thread.is_alive()

    def test_tcp_proxy_lifecycle(self, tcp_proxy, tcp_echo_server_port):
        proxy = tcp_proxy(target_address="127.0.0.1", target_port=tcp_echo_server_port)

        proxy.start()
        proxy.wait_is_up(timeout=5)

        with socket.create_connection(("127.0.0.1", proxy.port)) as c_sock:
            data = b"test data"
            c_sock.sendall(data)
            received_data = c_sock.recv(1024)
            assert received_data == data

        proxy.shutdown()
        proxy.join(5)
        assert not is_port_open(proxy.port)
