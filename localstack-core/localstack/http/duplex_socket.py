from __future__ import annotations

import logging
import socket
import ssl
from asyncio.selector_events import BaseSelectorEventLoop

from localstack.utils.asyncio import run_sync
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import Patch, patch

# set up logger
LOG = logging.getLogger(__name__)


class DuplexSocket(ssl.SSLSocket):
    """Simple duplex socket wrapper that allows serving HTTP/HTTPS over the same port."""

    def accept(self):
        newsock, addr = socket.socket.accept(self)
        if DuplexSocket.is_ssl_socket(newsock) is not False:
            newsock = self.context.wrap_socket(
                newsock,
                do_handshake_on_connect=self.do_handshake_on_connect,
                suppress_ragged_eofs=self.suppress_ragged_eofs,
                server_side=True,
            )

        return newsock, addr

    @staticmethod
    def is_ssl_socket(newsock):
        """Returns True/False if the socket uses SSL or not, or None if the status cannot be
        determined"""

        def peek_ssl_header():
            peek_bytes = 5
            first_bytes = newsock.recv(peek_bytes, socket.MSG_PEEK)
            if len(first_bytes or "") != peek_bytes:
                return
            first_byte = first_bytes[0]
            return first_byte < 32 or first_byte >= 127

        try:
            return peek_ssl_header()
        except Exception:
            # Fix for "[Errno 11] Resource temporarily unavailable" - This can
            #   happen if we're using a non-blocking socket in a blocking thread.
            newsock.setblocking(1)
            newsock.settimeout(1)
            try:
                return peek_ssl_header()
            except Exception:
                return False


@singleton_factory
def enable_duplex_socket():
    """
    Function which replaces the ssl.SSLContext.sslsocket_class with the DuplexSocket, enabling serving both,
    HTTP and HTTPS connections on a single port.
    """

    # set globally defined SSL socket implementation class
    Patch(ssl.SSLContext, "sslsocket_class", DuplexSocket).apply()

    if hasattr(BaseSelectorEventLoop, "_accept_connection2"):

        @patch(BaseSelectorEventLoop._accept_connection2)
        async def _accept_connection2(
            fn, self, protocol_factory, conn, extra, sslcontext, *args, **kwargs
        ):
            is_ssl_socket = await run_sync(DuplexSocket.is_ssl_socket, conn)
            if is_ssl_socket is False:
                sslcontext = None
            result = await fn(self, protocol_factory, conn, extra, sslcontext, *args, **kwargs)
            return result
