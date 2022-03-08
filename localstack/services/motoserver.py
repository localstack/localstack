import logging
import threading
from typing import Optional

from moto.server import DomainDispatcherApplication, create_backend_app
from werkzeug.serving import make_server

from localstack import constants
from localstack.utils.net import get_free_tcp_port
from localstack.utils.serving import Server

LOG = logging.getLogger(__name__)


class MotoServer(Server):
    def __init__(self, port: int, host: str = "localhost") -> None:
        super().__init__(port, host)
        self.server = make_server(
            self.host, self.port, app=DomainDispatcherApplication(create_backend_app), threaded=True
        )

    def do_run(self):
        try:
            LOG.info("starting moto server on %s", self.url)
            return self.server.serve_forever()
        finally:
            LOG.debug("moto server on %s returning", self.url)

    def do_shutdown(self):
        self.server.shutdown()


_mutex = threading.RLock()
_server: Optional[MotoServer] = None


def get_moto_server(timeout=10) -> MotoServer:
    """
    Returns the MotoServer singleton or creates it and waits for it to become ready.
    """
    global _server, _mutex

    with _mutex:
        if _server:
            return _server

        _server = MotoServer(port=get_free_tcp_port(), host=constants.BIND_HOST)
        _server.start()

        if not _server.wait_is_up(timeout):
            raise TimeoutError("gave up waiting for moto server on %s" % _server.url)

        return _server
