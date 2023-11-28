import logging
import ssl
import threading

import h11
from hypercorn import utils as hypercorn_utils
from hypercorn.asyncio import tcp_server
from hypercorn.config import Config
from hypercorn.events import Closed
from hypercorn.protocol import http_stream

from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# flag to avoid lowercasing all header names (e.g., some AWS S3 SDKs depend on "ETag" response header)
RETURN_CASE_SENSITIVE_HEADERS = True

# cache of SSL contexts (indexed by cert file names)
SSL_CONTEXTS = {}
SSL_LOCK = threading.RLock()


# FIXME this should be built-in features / a proper configuration of the hypercorn server (instead of monkeypatches)
def patch_http2_server():
    def InformationalResponse_init(self, *args, **kwargs):
        if kwargs.get("status_code") == 100 and not kwargs.get("reason"):
            # add missing "100 Continue" keyword which makes boto3 HTTP clients fail/hang
            kwargs["reason"] = "Continue"
        InformationalResponse_init_orig(self, *args, **kwargs)

    InformationalResponse_init_orig = h11.InformationalResponse.__init__
    h11.InformationalResponse.__init__ = InformationalResponse_init

    # skip error logging for ssl.SSLError in hypercorn tcp_server.py _read_data()

    async def _read_data(self) -> None:
        try:
            return await _read_data_orig(self)
        except Exception:
            await self.protocol.handle(Closed())

    _read_data_orig = tcp_server.TCPServer._read_data
    tcp_server.TCPServer._read_data = _read_data

    # skip error logging for ssl.SSLError in hypercorn tcp_server.py _close()

    async def _close(self) -> None:
        try:
            return await _close_orig(self)
        except ssl.SSLError:
            return

    _close_orig = tcp_server.TCPServer._close
    tcp_server.TCPServer._close = _close

    # avoid SSL context initialization errors when running multiple server threads in parallel

    def create_ssl_context(self, *args, **kwargs):
        with SSL_LOCK:
            key = "%s%s" % (self.certfile, self.keyfile)
            if key not in SSL_CONTEXTS:
                # perform retries to circumvent "ssl.SSLError: [SSL] PEM lib (_ssl.c:4012)"
                def _do_create():
                    SSL_CONTEXTS[key] = create_ssl_context_orig(self, *args, **kwargs)

                retry(_do_create, retries=3, sleep=0.5)
            return SSL_CONTEXTS[key]

    create_ssl_context_orig = Config.create_ssl_context
    Config.create_ssl_context = create_ssl_context

    # apply patch for case-sensitive header names (e.g., some AWS S3 SDKs depend on "ETag" case-sensitive header)
    def build_and_validate_headers(headers):
        validated_headers = []
        for name, value in headers:
            if name[0] == b":"[0]:
                raise ValueError("Pseudo headers are not valid")
            header_name = bytes(name) if RETURN_CASE_SENSITIVE_HEADERS else bytes(name).lower()
            validated_headers.append((header_name.strip(), bytes(value).strip()))
        return validated_headers

    hypercorn_utils.build_and_validate_headers = build_and_validate_headers
    http_stream.build_and_validate_headers = build_and_validate_headers

    # avoid "h11._util.LocalProtocolError: Too little data for declared Content-Length" for certain status codes

    def suppress_body(method, status_code):
        if status_code == 412:
            return False
        return suppress_body_orig(method, status_code)

    suppress_body_orig = hypercorn_utils.suppress_body
    hypercorn_utils.suppress_body = suppress_body
    http_stream.suppress_body = suppress_body
