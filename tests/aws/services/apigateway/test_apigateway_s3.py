import base64
import gzip
import json
import time

import pytest
import requests
import xmltodict
from botocore.exceptions import ClientError

from localstack.aws.api.apigateway import ContentHandlingStrategy
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY


@markers.aws.validated
# TODO: S3 does not return the HostId in the exception
@markers.snapshot.skip_snapshot_verify(paths=["$..Error.HostId"])
def test_apigateway_s3_any(
    aws_client, create_rest_apigw, s3_bucket, region_name, create_role_with_policy, snapshot
):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("RequestId"),
            snapshot.transform.key_value(
                "HostId", reference_replacement=False, value_replacement="<host-id>"
            ),
        ]
    )
    api_id, api_name, root_id = create_rest_apigw()
    stage_name = "test"
    object_name = "test.json"

    _, role_arn = create_role_with_policy(
        "Allow", "s3:*", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="{object_path+}"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
        requestParameters={
            "method.request.path.object_path": True,
            "method.request.header.Content-Type": False,
        },
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="ANY", statusCode="200"
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        integrationHttpMethod="ANY",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{{object_path}}",
        requestParameters={
            "integration.request.path.object_path": "method.request.path.object_path",
            "integration.request.header.Content-Type": "method.request.header.Content-Type",
        },
        credentials=role_arn,
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="ANY", statusCode="200"
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    invoke_url = api_invoke_url(api_id, stage_name, path="/" + object_name)

    def _get_object(assert_json: bool = False):
        _response = requests.get(url=invoke_url)
        assert _response.status_code == 200
        if assert_json:
            _response.json()
        return _response

    def _put_object(data: dict):
        _response = requests.put(
            url=invoke_url, json=data, headers={"Content-Type": "application/json"}
        )
        assert _response.status_code == 200

    # # Try to get an object that doesn't exist
    response = retry(_get_object, retries=10, sleep=2)
    snapshot.match("get-object-empty", xmltodict.parse(response.content))

    # Put a new object
    retry(lambda: _put_object({"put_id": 1}), retries=10, sleep=2)
    response = retry(lambda: _get_object(assert_json=True), retries=10, sleep=2)
    snapshot.match("get-object-1", response.text)

    # updated an object
    retry(lambda: _put_object({"put_id": 2}), retries=10, sleep=2)
    response = retry(lambda: _get_object(assert_json=True), retries=10, sleep=2)
    snapshot.match("get-object-2", response.text)

    # Delete an object
    requests.delete(invoke_url)
    response = retry(_get_object, retries=10, sleep=2)
    snapshot.match("get-object-deleted", xmltodict.parse(response.content))

    with pytest.raises(ClientError) as exc_info:
        aws_client.s3.get_object(Bucket=s3_bucket, Key=object_name)
    snapshot.match("get-object-s3", exc_info.value.response)

    # Make a POST request
    #  TODO AWS return a 200 with a message from s3 in xml format stating that POST is invalid
    # response = requests.post(invoke_url, headers={"Content-Type": "application/json"}, json={"put_id": 3})
    # snapshot.match("post-object", xmltodict.parse(response.content))


@markers.aws.validated
# TODO: S3 does not return the HostId in the exception
@markers.snapshot.skip_snapshot_verify(paths=["$.get-deleted-object.Error.HostId"])
def test_apigateway_s3_method_mapping(
    aws_client, create_rest_apigw, s3_bucket, region_name, create_role_with_policy, snapshot
):
    snapshot.add_transformers_list(
        [snapshot.transform.key_value("HostId"), snapshot.transform.key_value("RequestId")]
    )

    api_id, api_name, root_id = create_rest_apigw()
    stage_name = "test"
    object_name = "test.json"

    _, role_arn = create_role_with_policy(
        "Allow", "s3:*", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    get_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="get"
    )["id"]
    put_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="put"
    )["id"]
    delete_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="delete"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=get_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=put_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=delete_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=delete_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=put_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=get_resource_id, httpMethod="GET", statusCode="200"
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=get_resource_id,
        httpMethod="GET",
        integrationHttpMethod="GET",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        credentials=role_arn,
    )
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=put_resource_id,
        httpMethod="GET",
        integrationHttpMethod="PUT",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        requestParameters={
            "integration.request.header.Content-Type": "'application/json'",
        },
        requestTemplates={"application/json": '{"message": "great success!"}'},
        credentials=role_arn,
    )
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=delete_resource_id,
        httpMethod="GET",
        integrationHttpMethod="DELETE",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        credentials=role_arn,
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=get_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=put_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=delete_resource_id, httpMethod="GET", statusCode="200"
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    get_invoke_url = api_invoke_url(api_id, stage_name, path="/get")
    put_invoke_url = api_invoke_url(api_id, stage_name, path="/put")
    delete_invoke_url = api_invoke_url(api_id, stage_name, path="/delete")

    def _invoke(url, get_json: bool = False, get_xml: bool = False):
        response = requests.get(url=url)
        assert response.status_code == 200
        if get_json:
            response = response.json()
        elif get_xml:
            response = xmltodict.parse(response.text)
        return response

    retry(lambda: _invoke(put_invoke_url), retries=10, sleep=2)
    get_object = retry(lambda: _invoke(get_invoke_url, get_json=True), retries=10, sleep=3)
    snapshot.match("get-object", get_object)
    _invoke(delete_invoke_url)

    get_object = retry(lambda: _invoke(get_invoke_url, get_xml=True), retries=10, sleep=2)
    snapshot.match("get-deleted-object", get_object)


class TestApiGatewayS3BinarySupport:
    """
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings.html
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings-workflow.html
    """

    @pytest.fixture
    def setup_s3_apigateway(
        self,
        aws_client,
        s3_bucket,
        create_rest_apigw,
        create_role_with_policy,
        region_name,
        snapshot,
    ):
        def _setup(
            request_content_handling: ContentHandlingStrategy | None = None,
            response_content_handling: ContentHandlingStrategy | None = None,
            deploy: bool = True,
        ):
            api_id, api_name, root_id = create_rest_apigw()
            stage_name = "test"

            _, role_arn = create_role_with_policy(
                "Allow", "s3:*", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
            )

            resource_id = aws_client.apigateway.create_resource(
                restApiId=api_id, parentId=root_id, pathPart="{object_path+}"
            )["id"]

            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="ANY",
                authorizationType="NONE",
                requestParameters={
                    "method.request.path.object_path": True,
                    "method.request.header.Content-Type": False,
                    "method.request.header.response-content-type": False,
                },
            )

            aws_client.apigateway.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="ANY",
                statusCode="200",
                responseParameters={
                    "method.response.header.ETag": False,
                },
            )

            req_kwargs = {}
            if request_content_handling:
                req_kwargs["contentHandling"] = request_content_handling

            put_integration = aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="ANY",
                integrationHttpMethod="ANY",
                type="AWS",
                uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{{object_path}}",
                requestParameters={
                    "integration.request.path.object_path": "method.request.path.object_path",
                    "integration.request.header.Content-Type": "method.request.header.Content-Type",
                    "integration.request.querystring.response-content-type": "method.request.header.response-content-type",
                },
                credentials=role_arn,
                **req_kwargs,
            )
            snapshot.match("put-integration", put_integration)

            resp_kwargs = {}
            if response_content_handling:
                resp_kwargs["contentHandling"] = response_content_handling

            aws_client.apigateway.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod="ANY",
                statusCode="200",
                responseParameters={
                    "method.response.header.ETag": "integration.response.header.ETag",
                },
                **resp_kwargs,
            )

            if deploy:
                aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

            snapshot.add_transformers_list(
                [
                    snapshot.transform.key_value("cacheNamespace"),
                    snapshot.transform.key_value("credentials"),
                    snapshot.transform.regex(s3_bucket, replacement="<s3-bucket>"),
                ]
            )

            return api_id, resource_id, stage_name

        return _setup

    @markers.aws.validated
    @pytest.mark.parametrize("content_handling", [None, ContentHandlingStrategy.CONVERT_TO_TEXT])
    def test_apigw_s3_binary_support_request(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
        content_handling,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, _, stage_name = setup_s3_apigateway(
            request_content_handling=content_handling,
        )
        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        put_obj = aws_client.s3.put_object(
            Bucket=s3_bucket, Key="test-raw-key-etag", Body=object_body_raw
        )
        snapshot.match("put-obj-raw", put_obj)

        object_body_encoded = base64.b64encode(object_body_raw)
        object_body_text = "this is a UTF8 text typed object"

        object_key_raw = "binary-raw"
        object_key_encoded = "binary-encoded"
        object_key_text = "text"
        keys = [object_key_raw, object_key_encoded, object_key_text]

        def _invoke(url, body: bytes | str, content_type: str, expected_code: int = 200):
            _response = requests.put(url=url, data=body, headers={"Content-Type": content_type})
            assert _response.status_code == expected_code
            # sometimes S3 will respond 200, but will have a permission error
            assert not _response.content

            return _response

        invoke_url_raw = api_invoke_url(api_id, stage_name, path="/" + object_key_raw)
        retry(
            _invoke, retries=10, url=invoke_url_raw, body=object_body_raw, content_type="image/png"
        )

        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        retry(_invoke, url=invoke_url_encoded, body=object_body_encoded, content_type="image/png")

        invoke_url_text = api_invoke_url(api_id, stage_name, path="/" + object_key_text)
        retry(_invoke, url=invoke_url_text, body=object_body_text, content_type="image/png")

        for key in keys:
            get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
            snapshot.match(f"get-obj-no-binary-media-{key}", get_obj)

        # we now add a `binaryMediaTypes`
        patch_operations = [{"op": "add", "path": "/binaryMediaTypes/image~1png"}]
        aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patch_operations)

        if is_aws_cloud():
            time.sleep(10)

        stage_2 = "test2"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_2)

        invoke_url_raw_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_raw)
        invoke_url_encoded_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_encoded)
        invoke_url_text_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_text)

        # test with a ContentType that matches the binaryMediaTypes
        retry(
            _invoke,
            retries=10,
            url=invoke_url_raw_2,
            body=object_body_raw,
            content_type="image/png",
        )

        retry(_invoke, url=invoke_url_encoded_2, body=object_body_encoded, content_type="image/png")
        retry(_invoke, url=invoke_url_text_2, body=object_body_text, content_type="image/png")

        for key in keys:
            get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
            get_obj["Body"] = get_obj["Body"].read()
            snapshot.match(f"get-obj-binary-type-{key}", get_obj)

        # test with a ContentType that does not match the binaryMediaTypes
        retry(_invoke, url=invoke_url_raw_2, body=object_body_raw, content_type="text/plain")
        retry(
            _invoke, url=invoke_url_encoded_2, body=object_body_encoded, content_type="text/plain"
        )
        retry(_invoke, url=invoke_url_text_2, body=object_body_text, content_type="text/plain")

        for key in keys:
            get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
            get_obj["Body"] = get_obj["Body"].read()
            snapshot.match(f"get-obj-text-type-{key}", get_obj)

    @markers.aws.validated
    def test_apigw_s3_binary_support_request_convert_to_binary(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, _, stage_name = setup_s3_apigateway(
            request_content_handling=ContentHandlingStrategy.CONVERT_TO_BINARY,
        )
        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        put_obj = aws_client.s3.put_object(
            Bucket=s3_bucket, Key="test-raw-key-etag", Body=object_body_raw
        )
        snapshot.match("put-obj-raw", put_obj)

        object_body_encoded = base64.b64encode(object_body_raw)
        object_body_text = "this is a UTF8 text typed object"

        object_key_raw = "binary-raw"
        object_key_encoded = "binary-encoded"
        object_key_text = "text"
        keys = [object_key_raw, object_key_encoded, object_key_text]

        def _invoke(url, body: bytes | str, content_type: str, expected_code: int = 200):
            _response = requests.put(url=url, data=body, headers={"Content-Type": content_type})
            assert _response.status_code == expected_code
            # sometimes S3 will respond 200, but will have a permission error
            if expected_code == 200:
                assert not _response.content

            return _response

        # we start with Encoded here, because `raw` will trigger 500, which is also the error returned when the API
        # is not ready yet...
        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        retry(
            _invoke,
            url=invoke_url_encoded,
            body=object_body_encoded,
            content_type="image/png",
            retries=10,
        )
        get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key_encoded)
        get_obj["Body"] = get_obj["Body"].read()
        snapshot.match(f"get-obj-no-binary-media-{object_key_encoded}", get_obj)

        invoke_url_raw = api_invoke_url(api_id, stage_name, path="/" + object_key_raw)
        retry(
            _invoke,
            url=invoke_url_raw,
            body=object_body_raw,
            content_type="image/png",
            expected_code=500,
        )

        invoke_url_text = api_invoke_url(api_id, stage_name, path="/" + object_key_text)
        retry(
            _invoke,
            url=invoke_url_text,
            body=object_body_text,
            content_type="text/plain",
            expected_code=500,
        )

        for key in [object_key_raw, object_key_text]:
            with pytest.raises(aws_client.s3.exceptions.NoSuchKey):
                aws_client.s3.get_object(Bucket=s3_bucket, Key=key)

        # we now add a `binaryMediaTypes`
        patch_operations = [{"op": "add", "path": "/binaryMediaTypes/image~1png"}]
        aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patch_operations)

        if is_aws_cloud():
            time.sleep(10)

        stage_2 = "test2"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_2)

        invoke_url_raw_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_raw)
        invoke_url_encoded_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_encoded)
        invoke_url_text_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_text)

        # test with a ContentType that matches the binaryMediaTypes
        retry(
            _invoke,
            retries=10,
            url=invoke_url_raw_2,
            body=object_body_raw,
            content_type="image/png",
        )
        retry(_invoke, url=invoke_url_encoded_2, body=object_body_encoded, content_type="image/png")
        retry(_invoke, url=invoke_url_text_2, body=object_body_text, content_type="image/png")

        for key in keys:
            get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
            get_obj["Body"] = get_obj["Body"].read()
            snapshot.match(f"get-obj-binary-media-{key}", get_obj)

        # test with a ContentType that does not match the binaryMediaTypes
        retry(
            _invoke,
            url=invoke_url_raw_2,
            body=object_body_raw,
            content_type="text/plain",
            expected_code=500,
        )
        retry(
            _invoke,
            url=invoke_url_text_2,
            body=object_body_text,
            content_type="text/plain",
            expected_code=500,
        )

        retry(
            _invoke, url=invoke_url_encoded_2, body=object_body_encoded, content_type="text/plain"
        )
        get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key_encoded)
        get_obj["Body"] = get_obj["Body"].read()
        snapshot.match(f"get-obj-text-type-{object_key_encoded}", get_obj)

    @markers.aws.validated
    def test_apigw_s3_binary_support_request_convert_to_binary_with_request_template(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, resource_id, stage_name = setup_s3_apigateway(
            request_content_handling=ContentHandlingStrategy.CONVERT_TO_BINARY,
            deploy=False,
        )

        # set up the VTL requestTemplate
        aws_client.apigateway.update_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            patchOperations=[
                {
                    "op": "add",
                    "path": "/requestTemplates/application~1json",
                    "value": json.dumps({"data": "$input.body"}),
                }
            ],
        )

        get_integration = aws_client.apigateway.get_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
        )
        snapshot.match("get-integration", get_integration)

        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        object_body_encoded = base64.b64encode(object_body_raw)
        object_key_encoded = "binary-encoded"

        def _invoke(url, body: bytes | str, content_type: str, expected_code: int = 200):
            _response = requests.put(url=url, data=body, headers={"Content-Type": content_type})
            assert _response.status_code == expected_code
            # sometimes S3 will respond 200, but will have a permission error
            if expected_code == 200:
                assert not _response.content

            return _response

        # this request does not match the requestTemplates
        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        retry(
            _invoke,
            url=invoke_url_encoded,
            body=object_body_encoded,
            content_type="image/png",
            retries=10,
        )

        get_obj = aws_client.s3.get_object(Bucket=s3_bucket, Key=object_key_encoded)
        get_obj["Body"] = get_obj["Body"].read()
        snapshot.match("get-obj-encoded", get_obj)

        # this request matches the requestTemplates (application/json)
        # it fails because we cannot pass binary data that hasn't been sanitized to VTL templates
        retry(
            _invoke,
            url=invoke_url_encoded,
            body=object_body_encoded,
            content_type="application/json",
            expected_code=500,
        )

    @markers.aws.validated
    def test_apigw_s3_binary_support_response_no_content_handling(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, _, stage_name = setup_s3_apigateway(
            request_content_handling=None,
            response_content_handling=None,
        )
        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        object_body_encoded = base64.b64encode(object_body_raw)
        object_body_text = "this is a UTF8 text typed object"

        object_key_raw = "binary-raw"
        object_key_encoded = "binary-encoded"
        object_key_text = "text"
        keys_to_body = {
            object_key_raw: object_body_raw,
            object_key_encoded: object_body_encoded,
            object_key_text: object_body_text,
        }

        for key, obj_body in keys_to_body.items():
            put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=obj_body)
            snapshot.match(f"put-obj-{key}", put_obj)

        def _invoke(
            url, accept: str, r_content_type: str = "binary/octet-stream", expected_code: int = 200
        ):
            _response = requests.get(
                url=url, headers={"Accept": accept, "response-content-type": r_content_type}
            )
            assert _response.status_code == expected_code
            if expected_code == 200:
                assert _response.headers.get("ETag")

            return _response

        invoke_url_text = api_invoke_url(api_id, stage_name, path="/" + object_key_text)
        obj = retry(_invoke, url=invoke_url_text, accept="text/plain", retries=10)
        snapshot.match("text-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")})

        # it tries to decode the object as UTF8 and fails, hence 500
        invoke_url_raw = api_invoke_url(api_id, stage_name, path="/" + object_key_raw)
        obj = retry(_invoke, url=invoke_url_raw, accept="image/png")
        snapshot.match("raw-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")})

        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        obj = retry(_invoke, url=invoke_url_encoded, accept="image/png")
        snapshot.match(
            "encoded-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")}
        )

        # we now add a `binaryMediaTypes`
        patch_operations = [{"op": "add", "path": "/binaryMediaTypes/image~1png"}]
        aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patch_operations)

        if is_aws_cloud():
            time.sleep(10)

        stage_2 = "test2"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_2)

        invoke_url_encoded_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_encoded)
        invoke_url_raw_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_raw)
        invoke_url_text_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_text)

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="image/png", retries=20)
        snapshot.match(
            "encoded-payload-text-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # those 2 fails because we are in the text payload/binary accept -> Base64-decoded blob
        retry(_invoke, url=invoke_url_raw_2, accept="image/png", expected_code=500)
        retry(_invoke, url=invoke_url_text_2, accept="image/png", expected_code=500)

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        # those work because we're in the binary payload / binary accept -> Binary data
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="image/png", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="text/plain")
        snapshot.match(
            "encoded-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="text/plain")
        snapshot.match(
            "raw-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="text/plain")
        snapshot.match(
            "text-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="text/plain", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

    @markers.aws.validated
    def test_apigw_s3_binary_support_response_convert_to_text(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, _, stage_name = setup_s3_apigateway(
            request_content_handling=None,
            response_content_handling=ContentHandlingStrategy.CONVERT_TO_TEXT,
        )
        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        object_body_encoded = base64.b64encode(object_body_raw)
        object_body_text = "this is a UTF8 text typed object"

        object_key_raw = "binary-raw"
        object_key_encoded = "binary-encoded"
        object_key_text = "text"
        keys_to_body = {
            object_key_raw: object_body_raw,
            object_key_encoded: object_body_encoded,
            object_key_text: object_body_text,
        }

        for key, obj_body in keys_to_body.items():
            put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=obj_body)
            snapshot.match(f"put-obj-{key}", put_obj)

        def _invoke(
            url, accept: str, r_content_type: str = "binary/octet-stream", expected_code: int = 200
        ):
            _response = requests.get(
                url=url, headers={"Accept": accept, "response-content-type": r_content_type}
            )
            assert _response.status_code == expected_code
            if expected_code == 200:
                assert _response.headers.get("ETag")

            return _response

        invoke_url_text = api_invoke_url(api_id, stage_name, path="/" + object_key_text)
        obj = retry(_invoke, url=invoke_url_text, accept="text/plain", retries=10)
        snapshot.match("text-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")})

        # it tries to decode the object as UTF8 and fails, hence 500
        invoke_url_raw = api_invoke_url(api_id, stage_name, path="/" + object_key_raw)
        obj = retry(_invoke, url=invoke_url_raw, accept="image/png")
        snapshot.match("raw-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")})

        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        obj = retry(_invoke, url=invoke_url_encoded, accept="image/png")
        snapshot.match(
            "encoded-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")}
        )

        # we now add a `binaryMediaTypes`
        patch_operations = [{"op": "add", "path": "/binaryMediaTypes/image~1png"}]
        aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patch_operations)

        if is_aws_cloud():
            time.sleep(10)

        stage_2 = "test2"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_2)

        invoke_url_encoded_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_encoded)
        invoke_url_raw_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_raw)
        invoke_url_text_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_text)

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="image/png", retries=20)
        snapshot.match(
            "encoded-payload-text-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="image/png")
        snapshot.match(
            "raw-payload-text-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="image/png")
        snapshot.match(
            "text-payload-text-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="image/png", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="text/plain")
        snapshot.match(
            "encoded-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="text/plain")
        snapshot.match(
            "raw-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="text/plain")
        snapshot.match(
            "text-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="text/plain", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

    @markers.aws.validated
    def test_apigw_s3_binary_support_response_convert_to_binary(
        self,
        aws_client,
        s3_bucket,
        setup_s3_apigateway,
        snapshot,
    ):
        # the current API does not have any `binaryMediaTypes` configured
        api_id, _, stage_name = setup_s3_apigateway(
            request_content_handling=None,
            response_content_handling=ContentHandlingStrategy.CONVERT_TO_BINARY,
        )
        object_body_raw = gzip.compress(
            b"compressed data, should be invalid UTF-8 string", mtime=1676569620
        )
        with pytest.raises(ValueError):
            object_body_raw.decode()

        object_body_encoded = base64.b64encode(object_body_raw)
        object_body_text = "this is a UTF8 text typed object"

        object_key_raw = "binary-raw"
        object_key_encoded = "binary-encoded"
        object_key_text = "text"
        keys_to_body = {
            object_key_raw: object_body_raw,
            object_key_encoded: object_body_encoded,
            object_key_text: object_body_text,
        }

        for key, obj_body in keys_to_body.items():
            put_obj = aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body=obj_body)
            snapshot.match(f"put-obj-{key}", put_obj)

        def _invoke(
            url, accept: str, r_content_type: str = "binary/octet-stream", expected_code: int = 200
        ):
            _response = requests.get(
                url=url, headers={"Accept": accept, "response-content-type": r_content_type}
            )
            assert _response.status_code == expected_code
            if expected_code == 200:
                assert _response.headers.get("ETag")

            return _response

        invoke_url_encoded = api_invoke_url(api_id, stage_name, path="/" + object_key_encoded)
        obj = retry(_invoke, url=invoke_url_encoded, accept="image/png", retries=10)
        snapshot.match(
            "encoded-no-media", {"content": obj.content, "etag": obj.headers.get("ETag")}
        )

        # it tries to base64-decode the object and fails, hence 500
        invoke_url_raw = api_invoke_url(api_id, stage_name, path="/" + object_key_raw)
        retry(_invoke, url=invoke_url_raw, accept="image/png", expected_code=500)

        invoke_url_text = api_invoke_url(api_id, stage_name, path="/" + object_key_text)
        retry(_invoke, url=invoke_url_text, accept="text/plain", expected_code=500)

        # we now add a `binaryMediaTypes`
        patch_operations = [{"op": "add", "path": "/binaryMediaTypes/image~1png"}]
        aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patch_operations)

        if is_aws_cloud():
            time.sleep(10)

        stage_2 = "test2"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_2)

        invoke_url_encoded_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_encoded)
        invoke_url_raw_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_raw)
        invoke_url_text_2 = api_invoke_url(api_id, stage_2, path="/" + object_key_text)

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="image/png", retries=20)
        snapshot.match(
            "encoded-payload-text-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        retry(_invoke, url=invoke_url_raw_2, accept="image/png", expected_code=500)
        retry(_invoke, url=invoke_url_text_2, accept="image/png", expected_code=500)

        # test with Accept binary types (`Accept` that matches the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="image/png", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="image/png", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-binary",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and Text Payload (Payload `Content-Type` that does not match the binaryMediaTypes)
        obj = retry(_invoke, url=invoke_url_encoded_2, accept="text/plain")
        snapshot.match(
            "encoded-payload-text-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        retry(_invoke, url=invoke_url_raw_2, accept="text/plain", expected_code=500)
        retry(_invoke, url=invoke_url_text_2, accept="text/plain", expected_code=500)

        # test with Accept text types (`Accept` that does not match the binaryMediaTypes)
        # and binary Payload (Payload `Content-Type` that matches the binaryMediaTypes)
        obj = retry(
            _invoke, url=invoke_url_encoded_2, accept="text/plain", r_content_type="image/png"
        )
        snapshot.match(
            "encoded-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_raw_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "raw-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )

        obj = retry(_invoke, url=invoke_url_text_2, accept="text/plain", r_content_type="image/png")
        snapshot.match(
            "text-payload-binary-accept-text",
            {"content": obj.content, "etag": obj.headers.get("ETag")},
        )
