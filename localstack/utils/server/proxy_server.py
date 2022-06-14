import gzip
import logging
import os
import select
import socket
from typing import Any, Dict, Tuple, Union

import requests

from localstack.constants import BIND_HOST, HEADER_ACCEPT_ENCODING, LOCALHOST_IP
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.utils.asyncio import ensure_event_loop
from localstack.utils.files import new_tmp_file, save_file
from localstack.utils.functions import run_safe
from localstack.utils.numbers import is_number
from localstack.utils.strings import to_bytes
from localstack.utils.threads import TMP_THREADS, FuncThread, start_worker_thread

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
        s_dst.connect(ip_to_tuple(dst))

        sockets = [s_src, s_dst]

        try:
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


def start_ssl_proxy(
    port: int,
    target: PortOrUrl,
    target_ssl=False,
    client_cert_key: Tuple[str, str] = None,
    asynchronous: bool = False,
    fix_encoding: bool = False,
):
    """Start a proxy server that accepts SSL requests and forwards requests to a backend (either SSL or non-SSL)"""

    if fix_encoding:
        # use a custom proxy listener, in case the user provides client certificates for authentication
        if client_cert_key:
            server = _do_start_ssl_proxy_with_client_auth(
                port, target, client_cert_key=client_cert_key
            )
        else:
            server = _do_start_ssl_proxy_with_listener(port, target)
        if not asynchronous:
            server.join()
        return server

    def _run(*args):
        return _do_start_ssl_proxy(
            port, target, target_ssl=target_ssl, client_cert_key=client_cert_key
        )

    if not asynchronous:
        return _run()
    proxy = FuncThread(_run)
    TMP_THREADS.append(proxy)
    proxy.start()
    return proxy


def _save_cert_keys(client_cert_key: Tuple[str, str]) -> Tuple[str, str]:
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


def _do_start_ssl_proxy(
    port: int,
    target: PortOrUrl,
    target_ssl=False,
    client_cert_key: Tuple[str, str] = None,
    bind_address: str = "0.0.0.0",
):
    """
    Starts a tcp proxy (with tls) on the specified port

    :param port: Port the proxy should bind to
    :param target: Target of the proxy. If a port, it will connect to localhost:
    :param target_ssl: Specify if the proxy should connect to the target using SSL/TLS
    :param client_cert_key: Client certificate for the target connection. Only set if target_ssl=True
    :param bind_address: Bind address of the proxy server
    """
    import pproxy

    from localstack.services.generic_proxy import GenericProxy

    if ":" not in str(target):
        target = f"127.0.0.1:{target}"
    LOG.debug("Starting SSL proxy server %s -> %s", port, target)

    # create server and remote connection
    server = pproxy.Server(f"secure+tunnel://{bind_address}:{port}")
    target_proto = "ssl+tunnel" if target_ssl else "tunnel"
    remote = pproxy.Connection(f"{target_proto}://{target}")
    if client_cert_key:
        # TODO verify client certs server side?
        LOG.debug("Configuring ssl proxy to use client certs")
        cert_file, key_file = _save_cert_keys(client_cert_key=client_cert_key)
        remote.sslclient.load_cert_chain(certfile=cert_file, keyfile=key_file)
    args = dict(rserver=[remote])

    # set SSL contexts
    _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert()
    for context in pproxy.server.sslcontexts:
        context.load_cert_chain(cert_file_name, key_file_name)

    loop = ensure_event_loop()
    handler = loop.run_until_complete(server.start_server(args))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("exit!")

    handler.close()
    loop.run_until_complete(handler.wait_closed())
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()


def _do_start_ssl_proxy_with_client_auth(
    port: int, target: PortOrUrl, client_cert_key: Tuple[str, str]
):
    # prepare cert files (TODO: check whether/how we can pass cert strings to requests.request(..) directly)
    cert_params = _save_cert_keys(client_cert_key)
    # start proxy
    requests_kwargs = {"cert": cert_params}
    result = _do_start_ssl_proxy_with_listener(port, target, requests_kwargs=requests_kwargs)
    return result


def _do_start_ssl_proxy_with_listener(
    port: int, target: PortOrUrl, requests_kwargs: Dict[str, Any] = None
):
    target = f"http://localhost:{target}" if isinstance(target, int) else target
    base_url = f"{'https://' if '://' not in target else ''}{target.rstrip('/')}"
    requests_kwargs = requests_kwargs or {}

    # define forwarding listener
    class Listener(ProxyListener):
        def forward_request(self, method, path, data, headers):
            # send request to target
            url = f"{base_url}{path}"
            response = requests.request(
                method=method, url=url, data=data, headers=headers, verify=False, **requests_kwargs
            )
            # fix encoding of response, based on Accept-Encoding header
            if "gzip" in headers.get(HEADER_ACCEPT_ENCODING, "").lower():
                response._content = gzip.compress(to_bytes(response._content))
                response.headers["Content-Length"] = str(len(response._content))
                response.headers["Content-Encoding"] = "gzip"
            return response

    proxy_thread = start_proxy_server(port, update_listener=Listener(), use_ssl=True)
    return proxy_thread
