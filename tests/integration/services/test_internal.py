import pytest
import requests

from localstack import config


@pytest.mark.usefixtures("openapi_validate")
class TestInitScriptsResource:
    def test_stages_have_completed(self):
        response = requests.get(config.internal_service_url() + "/_localstack/init")
        assert response.status_code == 200
        doc = response.json()

        assert doc["completed"] == {
            "BOOT": True,
            "START": True,
            "READY": True,
            "SHUTDOWN": False,
        }

    def test_query_nonexisting_stage(self):
        response = requests.get(config.internal_service_url() + "/_localstack/init/does_not_exist")
        assert response.status_code == 404

    @pytest.mark.parametrize(
        ("stage", "completed"),
        [("boot", True), ("start", True), ("ready", True), ("shutdown", False)],
    )
    def test_query_individual_stage_completed(self, stage, completed):
        response = requests.get(config.internal_service_url() + f"/_localstack/init/{stage}")
        assert response.status_code == 200
        assert response.json()["completed"] == completed


@pytest.mark.usefixtures("openapi_validate")
class TestHealthResource:
    def test_get(self):
        response = requests.get(config.internal_service_url() + "/_localstack/health")
        assert response.ok
        assert "services" in response.json()
        assert "edition" in response.json()

    def test_head(self):
        response = requests.head(config.internal_service_url() + "/_localstack/health")
        assert response.ok
        assert not response.text


@pytest.mark.usefixtures("openapi_validate")
class TestInfoEndpoint:
    def test_get(self):
        response = requests.get(config.internal_service_url() + "/_localstack/info")
        assert response.ok
        doc = response.json()

        from localstack.constants import VERSION

        # we're being specifically vague here since we want this test to be robust against pro or community
        assert doc["version"].startswith(str(VERSION))
        assert doc["session_id"]
        assert doc["machine_id"]
        assert doc["system"]
        assert type(doc["is_license_activated"]) == bool
