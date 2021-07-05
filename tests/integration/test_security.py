import unittest

import requests

from localstack import config
from localstack.utils.aws import aws_stack


class TestCSRF(unittest.TestCase):
    def test_CSRF(self):
        headers = {"Origin": "http://attacker.com"}
        # Test if lambdas are enumerable
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers)
        self.assertEqual(403, response.status_code)

        # Test if config endpoint is reachable
        config_body = {"variable": "harmful", "value": "config"}

        response = requests.post(
            f"{config.get_edge_url()}/?_config_", headers=headers, json=config_body
        )
        self.assertEqual(403, response.status_code)

        # Test if endpoints are reachable without origin header
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/")
        self.assertEqual(200, response.status_code)
        self.assertEqual("*", response.headers["access-control-allow-origin"])

    def test_default_cors_headers(self):
        headers = {"Origin": "https://app.localstack.cloud"}
        response = requests.get(f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            "https://app.localstack.cloud",
            response.headers["access-control-allow-origin"],
        )
        self.assertIn("GET", response.headers["access-control-allow-methods"].split(","))

    def test_cors_s3_override(self):
        client = aws_stack.connect_to_service("s3")

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
        bucket_name = "my-s3-bucket"

        try:
            client.create_bucket(Bucket=bucket_name)
            client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=BUCKET_CORS_CONFIG)

            # create signed url
            url = client.generate_presigned_url(
                ClientMethod="put_object",
                Params={
                    "Bucket": bucket_name,
                    "Key": "424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf",
                    "ContentType": "application/pdf",
                    "ACL": "bucket-owner-full-control",
                },
                ExpiresIn=3600,
            )
            old_config = config.DISABLE_CUSTOM_CORS_S3
            config.DISABLE_CUSTOM_CORS_S3 = True
            result = requests.put(
                url,
                data="something",
                verify=False,
                headers={
                    "Origin": "https://localhost:4200",
                    "Content-Type": "application/pdf",
                },
            )
            self.assertEqual(403, result.status_code)
        finally:
            # cleanup
            config.DISABLE_CUSTOM_CORS_S3 = old_config
            client.delete_object(
                Bucket=bucket_name,
                Key="424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf",
            )
            client.delete_bucket(Bucket=bucket_name)

    def test_cors_disable(self):
        old_config = config.DISABLE_CORS_CHECKS
        try:
            headers = {"Origin": "https://invalid.localstack.cloud"}
            response = requests.get(
                f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers
            )
            self.assertEqual(403, response.status_code)

            config.DISABLE_CORS_CHECKS = True
            response = requests.get(
                f"{config.get_edge_url()}/2015-03-31/functions/", headers=headers
            )
            self.assertEqual(200, response.status_code)
            self.assertEqual(headers["Origin"], response.headers["access-control-allow-origin"])
            self.assertIn("GET", response.headers["access-control-allow-methods"].split(","))
        finally:
            # cleanup
            config.DISABLE_CORS_CHECKS = old_config
