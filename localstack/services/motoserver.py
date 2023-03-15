import logging

from moto.server import DomainDispatcherApplication, create_backend_app
from werkzeug.serving import make_server

from localstack import constants
from localstack.utils.net import get_free_tcp_port
from localstack.utils.objects import singleton_factory
from localstack.utils.patch import patch
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


@singleton_factory
def get_moto_server() -> MotoServer:
    """
    Returns the MotoServer singleton or creates it and waits for it to become ready.
    """
    server = MotoServer(port=get_free_tcp_port(), host=constants.BIND_HOST)
    server.start()

    if not server.wait_is_up(10):
        raise TimeoutError("gave up waiting for moto server on %s" % server.url)

    return server


@patch(DomainDispatcherApplication.get_application)
def get_application(fn, self, environ, *args, **kwargs):
    """
    Patch to fix an upstream issue where moto treats "/favicon.ico" as a special path, which
    can break clients attempting to upload favicon.ico files to S3 buckets.
    """
    if environ.get("PATH_INFO") == "/favicon.ico":
        environ["PATH_INFO"] = "/"
        try:
            return fn(self, environ, *args, **kwargs)
        finally:
            environ["PATH_INFO"] = "/favicon.ico"

    return fn(self, environ, *args, **kwargs)
