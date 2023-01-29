import os

from localstack.utils.files import load_file

# parent directory of this file
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENAPI_SPEC_PULUMI_JSON = os.path.join(PARENT_DIR, "files", "openapi.spec.pulumi.json")


def test_import_rest_api(import_apigw, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())

    spec_file = load_file(OPENAPI_SPEC_PULUMI_JSON)
    response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

    snapshot.match("import_rest_api", response)
