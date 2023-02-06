import pytest
import requests

from localstack.config import get_edge_url


class TestInitScriptsResource:
    def test_stages_have_completed(self):
        response = requests.get(get_edge_url() + "/_localstack/init")
        assert response.status_code == 200
        doc = response.json()

        assert doc["completed"] == {
            "BOOT": True,
            "START": True,
            "READY": True,
            "SHUTDOWN": False,
        }

    def test_query_nonexisting_stage(self):
        response = requests.get(get_edge_url() + "/_localstack/init/does_not_exist")
        assert response.status_code == 404

    @pytest.mark.parametrize(
        ("stage", "completed"),
        [("boot", True), ("start", True), ("ready", True), ("shutdown", False)],
    )
    def test_query_individual_stage_completed(self, stage, completed):
        response = requests.get(get_edge_url() + f"/_localstack/init/{stage}")
        assert response.status_code == 200
        assert response.json()["completed"] == completed


class TestHealthResource:
    def test_get(self):
        response = requests.get(get_edge_url() + "/_localstack/health")
        assert response.ok
        assert "services" in response.json()

    def test_head(self):
        response = requests.head(get_edge_url() + "/_localstack/health")
        assert response.ok
        assert not response.text
