import requests

from localstack import config
from localstack.testing.pytest import markers

CLOUDFORMATION_UI_PATH = "/_localstack/cloudformation/deploy"


class TestCloudFormationUi:
    @markers.aws.only_localstack
    def test_get_cloudformation_ui(self):
        cfn_ui_url = config.get_edge_url() + CLOUDFORMATION_UI_PATH
        response = requests.get(cfn_ui_url)

        # we simply test that the UI is available at the right path and that it returns HTML.
        assert response.ok
        assert "content-type" in response.headers
        # this is a bit fragile but assert that the file returned contains at least something related to the UI
        assert b"LocalStack" in response.content
