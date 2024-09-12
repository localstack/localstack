import importlib
import logging

from rolo.routing import RuleAdapter

from localstack import config
from localstack.aws.handlers.validation import OASPlugin
from localstack.http import Response
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.internal import get_internal_apis
from localstack.utils.files import rm_rf
from localstack.utils.ssl import get_cert_pem_file_path
from localstack.utils.swagger import SwaggerUIApi

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def deprecation_warnings() -> None:
    LOG.debug("Checking for the usage of deprecated community features and configs...")
    from localstack.deprecations import log_deprecation_warnings

    log_deprecation_warnings()


@hooks.on_infra_start(should_load=lambda: config.REMOVE_SSL_CERT)
def delete_cached_certificate():
    LOG.debug("Removing the cached local SSL certificate")
    target_file = get_cert_pem_file_path()
    rm_rf(target_file)


@hooks.on_infra_start()
def register_swagger_endpoints():
    get_internal_apis().add(SwaggerUIApi())

    def _serve_static_file(_request, path: str):
        module = importlib.import_module("localstack.static")
        return Response.for_resource(module, path)

    ROUTER.add(RuleAdapter("/static/<path:path>", _serve_static_file))


class CoreOASPlugin(OASPlugin):
    name = "localstack"
