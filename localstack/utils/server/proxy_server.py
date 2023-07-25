import logging
import os
import select
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Union

from localstack.constants import BIND_HOST, LOCALHOST_IP
from localstack.utils.files import new_tmp_file, save_file
from localstack.utils.functions import run_safe
from localstack.utils.numbers import is_number
from localstack.utils.serving import Server
from localstack.utils.ssl import create_ssl_cert
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)

BUFFER_SIZE = 2**10  # 1024
TLS_BUFFER_SIZE = 16384  # 16 KB, max TLS record size

PortOrUrl = Union[str, int]


def start_tcp_proxy(src, dst, handler, **kwargs):
    """Run a simple TCP proxy (tunneling raw connections from src to dst), using a message handler
        that can be used to intercept messages and return predefined responses for certain requests.

    Arguments:
    src -- Source IP address and port string. I.e.: '127.0.0.1:8000'
    dst -- Destination IP address and port. I.e.: '127.0.0.1:8888'
    handler -- a handler function to intercept requests (returns tuple (forward_value, response_value))
    """

    src = "%s:%s" % (BIND_HOST, src) if is_number(src) else src
    dst = "%s:%s" % (LOCALHOST_IP, dst) if is_number(dst) else dst
    thread = kwargs.get("_thread")

    def ip_to_tuple(ip):
        ip, port = ip.split(":")
        return ip, int(port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(ip_to_tuple(src))
    s.listen(1)
    s.settimeout(10)

    def handle_request(s_src, thread):
        s_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s_dst.connect(ip_to_tuple(dst))

            sockets = [s_src, s_dst]
            while thread.running:
                s_read, _, _ = select.select(sockets, [], [])

                for s in s_read:
                    data = s.recv(BUFFER_SIZE)
                    if data in [b"", "", None]:
                        return

                    if s == s_src:
                        forward, response = data, None
                        if handler:
                            forward, response = handler(data)
                        if forward is not None:
                            s_dst.sendall(forward)
                        elif response is not None:
                            s_src.sendall(response)
                            return
                    elif s == s_dst:
                        s_src.sendall(data)
        finally:
            run_safe(s_src.close)
            run_safe(s_dst.close)

    while thread.running:
        try:
            src_socket, _ = s.accept()
            start_worker_thread(lambda *args, _thread: handle_request(src_socket, _thread))
        except socket.timeout:
            pass


def _save_cert_keys(client_cert_key: tuple[str, str]) -> tuple[str, str]:
    """
    Save the given cert / key into files and returns their filename
    :param client_cert_key: tuple with (client_cert, client_key)
    :return: tuple of paths to files containing (client_cert, client_key)
    """
    cert_file = client_cert_key[0]
    if not os.path.exists(cert_file):
        cert_file = new_tmp_file()
        save_file(cert_file, client_cert_key[0])
    key_file = client_cert_key[1]
    if not os.path.exists(key_file):
        key_file = new_tmp_file()
        save_file(key_file, client_cert_key[1])
    return cert_file, key_file


class TLSProxyServer(Server):
    thread_pool: ThreadPoolExecutor
    client_certs: tuple[str, str]
    socket: socket.socket | None
    target_host: str
    target_port: str

    def __init__(
        self,
        port: int,
        target: str,
        host: str = "localhost",
        client_certs: tuple[str, str] | None = None,
    ):
        super().__init__(port, host)
        self.target_host, _, self.target_port = target.partition(":")
        self.thread_pool = ThreadPoolExecutor()
        self.client_certs = client_certs
        self.socket = None

    def _handle_socket(self, source_socket: ssl.SSLSocket, client_address: str) -> None:
        LOG.debug(
            "Handling connection from %s to %s:%s",
            client_address,
            self.target_host,
            self.target_port,
        )
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if self.client_certs:
                LOG.debug("Configuring ssl proxy to use client certs")
                cert_file, key_file = _save_cert_keys(client_cert_key=self.client_certs)
                context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            with socket.create_connection((self.target_host, int(self.target_port))) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as target_socket:
                    sockets = [source_socket, target_socket]
                    while not self._stopped.is_set():
                        s_read, _, _ = select.select(sockets, [], [])

                        for s in s_read:
                            data = s.recv(TLS_BUFFER_SIZE)
                            if not data:
                                return

                            if s == source_socket:
                                target_socket.sendall(data)
                            elif s == target_socket:
                                source_socket.sendall(data)
        except Exception as e:
            LOG.warning(
                "Error while proxying SSL request: %s", e, exc_info=LOG.isEnabledFor(logging.DEBUG)
            )
        finally:
            source_socket.close()
            LOG.debug("Connection finished!")

    def do_run(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        _, cert_file_name, key_file_name = create_ssl_cert()
        context.load_cert_chain(cert_file_name, key_file_name)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            self.socket = sock
            sock.bind((self.host, self.port))
            sock.listen()
            with context.wrap_socket(sock, server_side=True) as ssock:
                while not self._stopped.is_set():
                    try:
                        conn, addr = ssock.accept()
                        self.thread_pool.submit(self._handle_socket, conn, addr)
                    except ssl.SSLZeroReturnError:
                        pass
                    except Exception as e:
                        LOG.exception("Error accepting socket: %s", e)

    def do_shutdown(self):
        if self.socket:
            self.socket.close()
