import logging
import select
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class TCPProxy(Server):
    _target_address: str
    _target_port: int
    _handler: Callable[[bytes], tuple[bytes, bytes]] | None
    _buffer_size: int
    _thread_pool: ThreadPoolExecutor
    _server_socket: socket.socket | None

    def __init__(
        self,
        target_address: str,
        target_port: int,
        port: int,
        host: str,
        handler: Callable[[bytes], tuple[bytes, bytes]] = None,
    ) -> None:
        super().__init__(port, host)
        self._target_address = target_address
        self._target_port = target_port
        self._handler = handler
        self._buffer_size = 1024
        self._thread_pool = ThreadPoolExecutor(thread_name_prefix="tcp-proxy")
        self._server_socket = None

    def do_run(self):
        def handle_request(s_src: socket.socket):
            s_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with s_src as s_src, s_dst as s_dst:
                s_dst.connect((self._target_address, self._target_port))

                sockets = [s_src, s_dst]
                while self.is_running():
                    s_read, _, _ = select.select(sockets, [], [], 1)

                    for s in s_read:
                        data = s.recv(self._buffer_size)
                        if not data:
                            return

                        if s == s_src:
                            forward, response = data, None
                            if self._handler:
                                forward, response = self._handler(data)
                            if forward is not None:
                                s_dst.sendall(forward)
                            elif response is not None:
                                s_src.sendall(response)
                                return
                        elif s == s_dst:
                            s_src.sendall(data)

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(1)
        self._server_socket.settimeout(10)
        with self._server_socket:
            while self.is_running():
                try:
                    src_socket, _ = self._server_socket.accept()
                    self._thread_pool.submit(handle_request, src_socket)
                except socket.timeout:
                    pass
                except OSError as e:
                    # avoid creating an error message if OSError is thrown due to socket closing
                    if self.is_running():
                        LOG.warning("Error during during TCPProxy socket accept: %s", e)

    def do_shutdown(self):
        if self._server_socket:
            self._server_socket.shutdown(socket.SHUT_RDWR)
            self._server_socket.close()
        self._thread_pool.shutdown(cancel_futures=True)
