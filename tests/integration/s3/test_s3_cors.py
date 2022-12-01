import os

import pytest
import requests
import xmltodict
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.handlers.cors import ALLOWED_CORS_ORIGINS
from localstack.config import LEGACY_S3_PROVIDER
from localstack.constants import LOCALHOST_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.utils.strings import short_uid


def _bucket_url_vhost(bucket_name: str, region: str = "", localstack_host: str = None) -> str:
    if not region:
        region = config.AWS_REGION_US_EAST_1
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        if region == "us-east-1":
            return f"https://{bucket_name}.s3.amazonaws.com"
        else:
            return f"https://{bucket_name}.s3.{region}.amazonaws.com"
    host = localstack_host or (
        f"s3.{region}.{LOCALHOST_HOSTNAME}" if region != "us-east-1" else S3_VIRTUAL_HOSTNAME
    )
    s3_edge_url = config.get_edge_url(localstack_hostname=host)
    # TODO might add the region here
    return s3_edge_url.replace(f"://{host}", f"://{bucket_name}.{host}")


@pytest.fixture
def snapshot_headers(snapshot):
    # should remove localstack specific headers as well
    snapshot.add_transformer(
        [
            snapshot.transform.key_value("x-amz-id-2"),
            snapshot.transform.key_value("x-amz-request-id"),
            snapshot.transform.key_value("date", reference_replacement=False),
            snapshot.transform.key_value("Last-Modified", reference_replacement=False),
            snapshot.transform.key_value("server"),
        ]
    )


@pytest.fixture
def match_headers(snapshot, snapshot_headers):
    def _match(key: str, response: requests.Response):
        # lower case some server specific headers
        lower_case_headers = {"Date", "Server", "Accept-Ranges"}
        headers = {
            k if k not in lower_case_headers else k.lower(): v
            for k, v in dict(response.headers).items()
        }
        match_object = {
            "StatusCode": response.status_code,
            "Headers": headers,
        }
        if response.headers.get("Content-Type") in ("application/xml", "text/xml"):
            match_object["Body"] = xmltodict.parse(response.content)
        else:
            match_object["Body"] = response.text
        snapshot.match(key, match_object)

    return _match


@pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="Tests are for new ASF provider")
class TestS3Cors:
    @pytest.mark.aws_validated
    def test_cors_http_options_no_config(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("HostId", reference_replacement=False),
                snapshot.transform.key_value("RequestId"),
            ]
        )
        key = "test-cors-options-no-config"
        body = "cors-test"
        response = s3_client.put_object(Bucket=s3_bucket, Key=key, Body=body, ACL="public-read")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        key_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{key}"

        response = requests.options(key_url)
        assert response.status_code == 400
        # TODO: match_headers
        # yes, a body in an `options` request
        parsed_response = xmltodict.parse(response.content)
        snapshot.match("options-no-origin", parsed_response)

        response = requests.options(
            key_url, headers={"Origin": "whatever", "Access-Control-Request-Method": "PUT"}
        )
        assert response.status_code == 403
        parsed_response = xmltodict.parse(response.content)
        snapshot.match("options-with-origin", parsed_response)

    @pytest.mark.aws_validated
    def test_cors_http_get_no_config(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("HostId", reference_replacement=False),
                snapshot.transform.key_value("RequestId"),
            ]
        )
        key = "test-cors-get-no-config"
        body = "cors-test"
        response = s3_client.put_object(Bucket=s3_bucket, Key=key, Body=body, ACL="public-read")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        key_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{key}"

        response = requests.get(key_url)
        assert response.status_code == 200
        assert response.text == body
        assert not any("access-control" in header.lower() for header in response.headers)

        response = requests.get(key_url, headers={"Origin": "whatever"})
        assert response.status_code == 200
        assert response.text == body
        assert not any("access-control" in header.lower() for header in response.headers)

    @pytest.mark.only_localstack
    def test_cors_no_config_localstack_allowed(self, s3_client, s3_bucket):
        key = "test-cors-get-no-config"
        body = "cors-test"
        response = s3_client.put_object(Bucket=s3_bucket, Key=key, Body=body, ACL="public-read")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        key_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{key}"
        origin = ALLOWED_CORS_ORIGINS[0]

        response = requests.options(
            key_url, headers={"Origin": origin, "Access-Control-Request-Method": "PUT"}
        )
        assert response.ok
        assert response.headers["Access-Control-Allow-Origin"] == origin

        response = requests.get(key_url, headers={"Origin": origin})
        assert response.status_code == 200
        assert response.text == body
        assert response.headers["Access-Control-Allow-Origin"] == origin

    @pytest.mark.aws_validated
    def test_cors_http_options_non_existent_bucket(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(
            [
                snapshot.transform.key_value("HostId", reference_replacement=False),
                snapshot.transform.key_value("RequestId"),
            ]
        )
        key = "test-cors-options-no-bucket"
        key_url = (
            f'{_bucket_url_vhost(bucket_name=f"fake-bucket-{short_uid()}-{short_uid()}")}/{key}'
        )

        response = requests.options(key_url)
        assert response.status_code == 400
        parsed_response = xmltodict.parse(response.content)
        snapshot.match("options-no-origin", parsed_response)

        response = requests.options(key_url, headers={"Origin": "whatever"})
        assert response.status_code == 403
        parsed_response = xmltodict.parse(response.content)
        snapshot.match("options-with-origin", parsed_response)

    @pytest.mark.only_localstack
    def test_cors_http_options_non_existent_bucket_ls_allowed(self, s3_client, s3_bucket):
        key = "test-cors-options-no-bucket"
        key_url = f'{_bucket_url_vhost(bucket_name=f"fake-bucket-{short_uid()}")}/{key}'
        origin = ALLOWED_CORS_ORIGINS[0]
        response = requests.options(key_url, headers={"Origin": origin})
        assert response.ok
        assert response.headers["Access-Control-Allow-Origin"] == origin

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Body.Error.HostId",  # it's because HostId is supposed to match x-amz-id-2 but is handled in serializer
            "$..Body.Error.RequestId",  # it's because RequestId is supposed to match x-amz-request-id ^
            "$..Headers.Connection",  # TODO: fix me? OPTIONS with body is missing it
            "$..Headers.Content-Length",  # TODO: fix me? not supposed to be here, OPTIONS with body
            "$..Headers.Transfer-Encoding",  # TODO: fix me? supposed to be chunked, fully missing for OPTIONS with body (to be expected, honestly)
        ]
    )
    def test_cors_match_origins(self, s3_client, s3_bucket, match_headers, monkeypatch):
        # monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", False)
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["https://localhost:4200"],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        object_key = "test-cors-123"
        response = s3_client.put_object(
            Bucket=s3_bucket, Key=object_key, Body="test-cors", ACL="public-read"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=bucket_cors_config)

        key_url = f"{_bucket_url_vhost(bucket_name=s3_bucket)}/{object_key}"

        # no origin, akin to no CORS
        opt_req = requests.options(key_url)
        match_headers("opt-no-origin", opt_req)
        get_req = requests.get(key_url)
        match_headers("get-no-origin", get_req)

        # origin from the rule
        opt_req = requests.options(
            key_url,
            headers={"Origin": "https://localhost:4200", "Access-Control-Request-Method": "PUT"},
        )
        match_headers("opt-right-origin", opt_req)
        get_req = requests.get(key_url, headers={"Origin": "https://localhost:4200"})
        match_headers("get-right-origin", get_req)

        # wrong origin
        opt_req = requests.options(
            key_url,
            headers={"Origin": "http://localhost:4200", "Access-Control-Request-Method": "PUT"},
        )
        match_headers("opt-wrong-origin", opt_req)
        get_req = requests.get(key_url, headers={"Origin": "http://localhost:4200"})
        match_headers("get-wrong-origin", get_req)

        # test * origin
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET", "PUT"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=bucket_cors_config)
        # random origin
        opt_req = requests.options(
            key_url,
            headers={"Origin": "http://random:1234", "Access-Control-Request-Method": "PUT"},
        )
        match_headers("opt-random-wildcard-origin", opt_req)
        get_req = requests.get(key_url, headers={"Origin": "http://random:1234"})
        match_headers("get-random-wildcard-origin", get_req)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Body.Error.HostId",  # it's because HostId is supposed to match x-amz-id-2 but is handled in serializer
            "$..Body.Error.RequestId",  # it's because RequestId is supposed to match x-amz-request-id ^
            "$..Headers.Connection",  # TODO: fix me? OPTIONS with body is missing it
            "$..Headers.Content-Length",  # TODO: fix me? not supposed to be here, OPTIONS with body
            "$..Headers.Transfer-Encoding",  # TODO: fix me? supposed to be chunked, fully missing for OPTIONS with body (to be expected, honestly)
            "$.put-op.Body",  # TODO: We should not return a body for almost all PUT requests
            "$.put-op.Headers.Content-Type",  # issue with default Response values
        ]
    )
    def test_cors_match_methods(self, s3_client, s3_create_bucket, match_headers, monkeypatch):
        # monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", False)
        origin = "https://localhost:4200"
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [origin],
                    "AllowedMethods": ["GET"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        object_key = "test-cors-method"
        bucket_name = s3_create_bucket(ACL="public-read-write")
        response = s3_client.put_object(
            Bucket=bucket_name, Key=object_key, Body="test-cors", ACL="public-read"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        key_url = f"{_bucket_url_vhost(bucket_name=bucket_name)}/{object_key}"

        # test with allowed method: GET
        opt_req = requests.options(
            key_url, headers={"Origin": origin, "Access-Control-Request-Method": "GET"}
        )
        match_headers("opt-get", opt_req)
        # try a get with a supposed OPTIONS headers, to check behaviour (AWS is weird about it)
        get_req = requests.get(
            key_url, headers={"Origin": origin, "Access-Control-Request-Method": "PUT"}
        )
        match_headers("get-wrong-op", get_req)

        get_req = requests.get(key_url, headers={"Origin": origin})
        match_headers("get-op", get_req)

        # test with method: PUT
        new_key_url = f"{_bucket_url_vhost(bucket_name=bucket_name)}/{object_key}new"
        opt_req = requests.options(
            new_key_url, headers={"Origin": origin, "Access-Control-Request-Method": "PUT"}
        )
        match_headers("opt-put", opt_req)
        get_req = requests.put(new_key_url, headers={"Origin": origin})
        match_headers("put-op", get_req)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Body.Error.HostId",  # it's because HostId is supposed to match x-amz-id-2 but is handled in serializer
            "$..Body.Error.RequestId",  # it's because RequestId is supposed to match x-amz-request-id ^
            "$..Headers.Connection",  # TODO: fix me? OPTIONS with body is missing it
            "$..Headers.Content-Length",  # TODO: fix me? not supposed to be here, OPTIONS with body
            "$..Headers.Transfer-Encoding",
            # TODO: fix me? supposed to be chunked, fully missing for OPTIONS with body (to be expected, honestly)
            "$.put-op.Body",  # TODO: We should not return a body for almost all PUT requests
            "$.put-op.Headers.Content-Type",  # issue with default Response values
        ]
    )
    def test_cors_match_headers(self, s3_client, s3_create_bucket, match_headers, monkeypatch):
        # monkeypatch.setattr(config, "DISABLE_CUSTOM_CORS_S3", False)
        origin = "https://localhost:4200"
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [origin],
                    "AllowedMethods": ["GET"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": ["*"],
                }
            ]
        }

        object_key = "test-cors-method"
        bucket_name = s3_create_bucket(ACL="public-read-write")
        response = s3_client.put_object(
            Bucket=bucket_name, Key=object_key, Body="test-cors", ACL="public-read"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        key_url = f"{_bucket_url_vhost(bucket_name=bucket_name)}/{object_key}"

        # test with a specific header: x-amz-request-payer
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-amz-request-payer",
            },
        )
        match_headers("opt-get", opt_req)
        # test with two specific headers: x-amz-request-payer & x-amz-expected-bucket-owner
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-amz-request-payer, x-amz-expected-bucket-owner",
            },
        )
        match_headers("opt-get-two", opt_req)
        get_req = requests.get(
            key_url, headers={"Origin": origin, "x-amz-request-payer": "requester"}
        )
        match_headers("get-op", get_req)

        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [origin],
                    "AllowedMethods": ["GET"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": [
                        "x-amz-expected-bucket-owner",
                        "x-amz-server-side-encryption-customer-algorithm",
                    ],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        # test with a specific header: x-amz-request-payer, but not allowed in the config
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-amz-request-payer",
            },
        )
        match_headers("opt-get-non-allowed", opt_req)
        assert opt_req.status_code == 403

        # test with a specific header: x-amz-expected-bucket-owner, allowed in the config
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-amz-expected-bucket-owner",
            },
        )
        match_headers("opt-get-allowed", opt_req)
        assert opt_req.ok

        # test GET with Access-Control-Request-Headers: should not happen in reality, AWS is considering it like an
        # OPTIONS request
        get_req = requests.get(
            key_url,
            headers={
                "Origin": origin,
                "Access-Control-Request-Headers": "x-amz-request-payer",
            },
        )
        # no CORS in the headers
        match_headers("get-non-allowed-with-acl", get_req)

        # test GET with x-amz-request-payer in non-allowed headers, should work when Access-Control-Request-Headers
        # is not present
        get_req = requests.get(
            key_url,
            headers={
                "Origin": origin,
                "x-amz-request-payer": "requester",
            },
        )
        match_headers("get-non-allowed", get_req)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$.opt-get.Headers.Content-Type",  # issue with default Response values
        ]
    )
    def test_cors_expose_headers(self, s3_client, s3_create_bucket, match_headers):
        object_key = "test-cors-expose"
        bucket_name = s3_create_bucket(ACL="public-read-write")
        response = s3_client.put_object(
            Bucket=bucket_name, Key=object_key, Body="test-cors", ACL="public-read"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # ExposeHeaders allows the browser to access those headers from the response
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET"],
                    "ExposeHeaders": ["x-amz-id-2", "x-amz-request-id", "x-amz-request-payer"],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        key_url = f"{_bucket_url_vhost(bucket_name=bucket_name)}/{object_key}"

        # get CORS headers from the response matching the rule
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": "localhost:4566",
                "Access-Control-Request-Method": "GET",
            },
        )
        match_headers("opt-get", opt_req)

    @pytest.mark.aws_validated
    def test_get_cors(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_cors(Bucket=s3_bucket)

        snapshot.match("get-cors-no-set", e.value.response)

        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET"],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=bucket_cors_config)

        response = s3_client.get_bucket_cors(Bucket=s3_bucket)
        snapshot.match("get-cors-after-set", response)

    @pytest.mark.aws_validated
    def test_put_cors(self, s3_client, s3_bucket, snapshot):
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [
                        "https://test.com",
                        "https://app.test.com",
                        "http://test.com:80",
                    ],
                    "AllowedMethods": ["GET", "PUT", "HEAD"],
                    "MaxAgeSeconds": 3000,
                    "AllowedHeaders": [
                        "x-amz-expected-bucket-owner",
                        "x-amz-server-side-encryption-customer-algorithm",
                    ],
                }
            ]
        }
        put_response = s3_client.put_bucket_cors(
            Bucket=s3_bucket, CORSConfiguration=bucket_cors_config
        )
        snapshot.match("put-cors", put_response)

        response = s3_client.get_bucket_cors(Bucket=s3_bucket)
        snapshot.match("get-cors", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Body.Error.HostId",  # it's because HostId is supposed to match x-amz-id-2 but is handled in serializer
            "$..Body.Error.RequestId",  # it's because RequestId is supposed to match x-amz-request-id ^
            "$..Headers.Content-Length",  # TODO: fix me? not supposed to be here, OPTIONS with body
            "$..Headers.Transfer-Encoding",
        ]
    )
    def test_put_cors_default_values(self, s3_client, s3_create_bucket, match_headers):
        object_key = "test-cors-default"
        bucket_name = s3_create_bucket(ACL="public-read-write")
        response = s3_client.put_object(
            Bucket=bucket_name, Key=object_key, Body="test-cors", ACL="public-read"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # don't set MaxAge, AllowHeaders and ExposeHeaders
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET"],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=bucket_cors_config)

        key_url = f"{_bucket_url_vhost(bucket_name=bucket_name)}/{object_key}"

        # get CORS headers from the response matching the rule
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": "localhost:4566",
                "Access-Control-Request-Method": "GET",
            },
        )
        match_headers("opt-get", opt_req)

        # get CORS headers from the response not matching the rule because AllowedHeaders is missing from the rule
        opt_req = requests.options(
            key_url,
            headers={
                "Origin": "localhost:4566",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "x-amz-request-payer",
            },
        )
        match_headers("opt-get-headers", opt_req)

    @pytest.mark.aws_validated
    def test_put_cors_invalid_rules(self, s3_client, s3_bucket, snapshot):
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*", "https://test.com"],
                    "AllowedMethods": ["GET", "PUT", "HEAD", "MYMETHOD"],
                }
            ]
        }
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=bucket_cors_config)

        snapshot.match("put-cors-exc", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration={"CORSRules": []})

        snapshot.match("put-cors-exc-empty", e.value.response)

    @pytest.mark.aws_validated
    def test_put_cors_empty_origin(self, s3_client, s3_bucket, snapshot):
        # derived from TestAccS3Bucket_Security_corsEmptyOrigin TF test
        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": [""],
                    "AllowedMethods": ["GET", "PUT", "HEAD"],
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=s3_bucket, CORSConfiguration=bucket_cors_config)

        response = s3_client.get_bucket_cors(Bucket=s3_bucket)

        snapshot.match("get-cors-empty", response)

    @pytest.mark.aws_validated
    def test_delete_cors(self, s3_client, s3_bucket, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        response = s3_client.delete_bucket_cors(Bucket=s3_bucket)
        snapshot.match("delete-cors-before-set", response)

        bucket_cors_config = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET"],
                }
            ]
        }
        put_response = s3_client.put_bucket_cors(
            Bucket=s3_bucket, CORSConfiguration=bucket_cors_config
        )
        snapshot.match("put-cors", put_response)

        response = s3_client.get_bucket_cors(Bucket=s3_bucket)
        snapshot.match("get-cors", response)

        response = s3_client.delete_bucket_cors(Bucket=s3_bucket)
        snapshot.match("delete-cors", response)

        with pytest.raises(ClientError) as e:
            s3_client.get_bucket_cors(Bucket=s3_bucket)

        snapshot.match("get-cors-deleted", e.value.response)
