import pytest
import requests

from localstack import config
from localstack.testing.aws.lambda_utils import is_new_provider
from localstack.utils.aws import aws_stack
from localstack.utils.strings import to_str


class TestCSRF:
    def test_CSRF(self):
        headers = {"Origin": "http://attacker.com"}
        # Test if lambdas are enumerable
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers)
        assert response.status_code == 403

        # Test if config endpoint is reachable
        config_body = {"variable": "harmful", "value": "config"}

        response = requests.post(
            f"{config.get_edge_url()}/?_config_", headers=headers, json=config_body
        )
        assert response.status_code == 403

        # Test if endpoints are reachable without origin header
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/")
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "*"

    def test_default_cors_headers(self):
        headers = {"Origin": "https://app.localstack.cloud"}
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://app.localstack.cloud"
        assert "GET" in response.headers["access-control-allow-methods"].split(",")

    @pytest.mark.parametrize("path", ["/health", "/_localstack/health"])
    def test_internal_route_cors_headers(self, path):
        headers = {"Origin": "https://app.localstack.cloud"}
        response = requests.get(f"{config.get_edge_url()}{path}", headers=headers)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://app.localstack.cloud"
        assert "GET" in response.headers["access-control-allow-methods"].split(",")

    def test_cors_s3_override(self, s3_client, s3_bucket, monkeypatch):
        monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", True)

        BUCKET_CORS_CONFIG = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["https://localhost:4200"],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=BUCKET_CORS_CONFIG)

        # create signed url
        url = s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": s3_bucket,
                "Key": "424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf",
                "ContentType": "application/pdf",
                "ACL": "bucket-owner-full-control",
            },
            ExpiresIn=3600,
        )
        result = requests.put(
            url,
            data="something",
            verify=False,
            headers={
                "Origin": "https://localhost:4200",
                "Content-Type": "application/pdf",
            },
        )
        assert result.status_code == 403

    @pytest.mark.skipif(condition=is_new_provider(), reason="invalid API behavior")
    def test_disable_cors_checks(self, monkeypatch):
        """Test DISABLE_CORS_CHECKS=1 (most permissive setting)"""
        headers = {"Origin": "https://invalid.localstack.cloud"}
        url = f"{config.get_edge_url()}/2015-03-31/functions/"
        response = requests.get(url, headers=headers)
        assert response.status_code == 403

        monkeypatch.setattr(config, "DISABLE_CORS_CHECKS", True)
        response = requests.get(url, headers=headers)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == headers["Origin"]
        assert "GET" in response.headers["access-control-allow-methods"].split(",")

    def test_disable_cors_headers(self, monkeypatch):
        """Test DISABLE_CORS_CHECKS=1 (most restrictive setting, not sending any CORS headers)"""
        headers = aws_stack.mock_aws_request_headers("sns")
        headers["Origin"] = "https://app.localstack.cloud"
        url = config.get_edge_url()
        data = {"Action": "ListTopics", "Version": "2010-03-31"}
        response = requests.post(url, headers=headers, data=data)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == headers["Origin"]
        assert "authorization" in response.headers["access-control-allow-headers"].lower()
        assert "GET" in response.headers["access-control-allow-methods"].split(",")
        assert "<ListTopicsResponse" in to_str(response.content)

        monkeypatch.setattr(config, "DISABLE_CORS_HEADERS", True)
        response = requests.post(url, headers=headers, data=data)
        assert response.status_code == 200
        assert "<ListTopicsResponse" in to_str(response.content)
        assert not response.headers.get("access-control-allow-headers")
        assert not response.headers.get("access-control-allow-methods")
        assert not response.headers.get("access-control-allow-origin")
        assert not response.headers.get("access-control-allow-credentials")
