import logging
import select
import socket
from typing import Union

from localstack.constants import BIND_HOST, LOCALHOST_IP
from localstack.utils.functions import run_safe
from localstack.utils.numbers import is_number
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)

BUFFER_SIZE = 2**10  # 1024

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
