from rolo import Request

from localstack.services.cloudformation.deploy_ui import CloudFormationUi


class TestCloudFormationUiResource:
    def test_get(self):
        resource = CloudFormationUi()
        response = resource.on_get(Request("GET", "/", body=b"None"))
        assert response.status == "200 OK"
        assert "</html>" in response.get_data(as_text=True), "deploy UI did not render HTML"
        assert "text/html" in response.headers.get("content-type", "")
