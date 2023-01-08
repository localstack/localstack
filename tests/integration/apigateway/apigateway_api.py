import pytest

from localstack.utils.files import load_file
from tests.integration.apigateway import OPENAPI_SPEC_PULUMI_JSON
from tests.integration.apigateway_fixtures import delete_rest_api, import_rest_api


@pytest.fixture
def import_apigw(apigateway_client):
    rest_api_ids = []

    def _import_apigateway_function(*args, **kwargs):
        response, root_id = import_rest_api(apigateway_client, **kwargs)
        rest_api_ids.append(response.get("id"))
        return response, root_id

    yield _import_apigateway_function

    for rest_api_id in rest_api_ids:
        delete_rest_api(apigateway_client, restApiId=rest_api_id)


def test_import_rest_api(import_apigw, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())

    spec_file = load_file(OPENAPI_SPEC_PULUMI_JSON)
    response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

    snapshot.match("import_rest_api", response)
