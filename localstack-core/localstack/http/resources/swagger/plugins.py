import werkzeug
import yaml
from rolo.routing import RuleAdapter

from localstack.http.resources.swagger.endpoints import SwaggerUIApi
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.internal import get_internal_apis
from localstack.utils.openapi import get_localstack_openapi_spec


@hooks.on_infra_start()
def register_swagger_endpoints():
    get_internal_apis().add(SwaggerUIApi())

    def _serve_openapi_spec(_request):
        spec = get_localstack_openapi_spec()
        response_body = yaml.dump(spec)
        return werkzeug.Response(
            response_body, content_type="application/yaml", direct_passthrough=True
        )

    ROUTER.add(RuleAdapter("/openapi.yaml", _serve_openapi_spec))
