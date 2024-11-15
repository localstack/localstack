import json

import pytest
import requests

from localstack import config
from localstack.utils.strings import to_str


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


def verify_stream_response(resource_type, region, resource):
    data = json.loads(to_str(resource))
    return (
        resource_type in data,
        any(x["region_name"] == region for x in data[resource_type]),
    )


class TestResourcesEndpoint:
    resources_endpoint = config.internal_service_url() + "/_localstack/resources"

    def request_and_assert(self, resource_type, region):
        with requests.get(self.resources_endpoint, stream=True) as response:
            assert any(
                verify_stream_response(resource_type, region, resource)
                for resource in response.iter_lines()
                if resource
            )

    def test_get_resource(self, aws_client):
        resource_type = "AWS::SNS::Topic"
        region = "us-east-1"
        aws_client.sns.create_topic(Name="test")

        self.request_and_assert(resource_type, region)

    def test_get_global_resource(self, aws_client):
        resource_type = "AWS::S3::Bucket"
        region = "global"
        aws_client.s3.create_bucket(Bucket="test")

        self.request_and_assert(resource_type, region)
