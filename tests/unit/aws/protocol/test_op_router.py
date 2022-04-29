import pytest
from werkzeug.exceptions import NotFound

from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.aws.spec import list_services, load_service
from localstack.http import Request


def _collect_services():
    for service in list_services():
        if service.protocol.startswith("rest"):
            yield service.service_name


@pytest.mark.parametrize(
    "service",
    _collect_services(),
)
@pytest.mark.param
def test_create_op_router_works_for_every_service(service):
    router = RestServiceOperationRouter(load_service(service))

    try:
        router.match(Request("GET", "/"))
    except NotFound:
        pass
