import logging
import select
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class TCPProxy(Server):
    """
    Server based TCP proxy abstraction.
    This uses a ThreadPoolExecutor, so the maximum number of parallel connections is limited.
    """

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
        # thread pool limited to 64 workers for now - can be increased or made configurable if this should not suffice
        # for certain use cases
        self._thread_pool = ThreadPoolExecutor(thread_name_prefix="tcp-proxy", max_workers=64)
        self._server_socket = None

    def _handle_request(self, s_src: socket.socket):
        try:
            s_dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with s_src as s_src, s_dst as s_dst:
                s_dst.connect((self._target_address, self._target_port))

                sockets = [s_src, s_dst]
                while not self._stopped.is_set():
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
        except Exception as e:
            LOG.error(
                "Error while handling request from %s to %s:%s: %s",
                s_src.getpeername(),
                self._target_address,
                self._target_port,
                e,
            )

    def do_run(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(1)
        self._server_socket.settimeout(10)
        LOG.debug(
            "Starting TCP proxy bound on %s:%s forwarding to %s:%s",
            self.host,
            self.port,
            self._target_address,
            self._target_port,
        )

        with self._server_socket:
            while not self._stopped.is_set():
                try:
                    src_socket, _ = self._server_socket.accept()
                    self._thread_pool.submit(self._handle_request, src_socket)
                except socket.timeout:
                    pass
                except OSError as e:
                    # avoid creating an error message if OSError is thrown due to socket closing
                    if not self._stopped.is_set():
                        LOG.warning("Error during during TCPProxy socket accept: %s", e)

    def do_shutdown(self):
        if self._server_socket:
            self._server_socket.shutdown(socket.SHUT_RDWR)
            self._server_socket.close()
        self._thread_pool.shutdown(cancel_futures=True)
        LOG.debug("Shut down TCPProxy on %s:%s", self.host, self.port)
