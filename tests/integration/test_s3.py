# TODO: migrate tests to tests/integration/s3/
#  DO NOT ADD ADDITIONAL TESTS HERE. USE PYTEST AND RUN TESTS AGAINST AWS!
import base64
import gzip
import hashlib
import json
import os
import shutil
import unittest
from io import BytesIO
from urllib.request import Request

import boto3
import pytest
import requests
from botocore.client import Config

from localstack import config
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.services.awslambda.lambda_api import use_docker
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_NODEJS14X
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import new_tmp_dir, run, short_uid, to_bytes, to_str

TEST_BUCKET_NAME_WITH_POLICY = "test-bucket-policy-1"
TEST_BUCKET_WITH_VERSIONING = "test-bucket-versioning-1"

TEST_BUCKET_NAME_2 = "test-bucket-2"
TEST_KEY_2 = "test-key-2"
TEST_GET_OBJECT_RANGE = 17

TEST_REGION_1 = "eu-west-1"

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_DOWNLOAD_FROM_S3 = os.path.join(
    THIS_FOLDER, "awslambda", "functions", "lambda_triggered_by_sqs_download_s3_file.py"
)

BATCH_DELETE_BODY = """
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object>
    <Key>%s</Key>
  </Object>
  <Object>
    <Key>%s</Key>
  </Object>
</Delete>
"""


class PutRequest(Request):
    """Class to handle putting with urllib"""

    def __init__(self, *args, **kwargs):
        Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return "PUT"


# def test_host_and_path_addressing(wrapped):
#     """ Decorator that runs a test method with both - path and host style addressing. """
#     # TODO - needs to be fixed below!
#     def wrapper(self):
#         try:
#             # test via path based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.create_external_boto_client('s3', config={'addressing_style': 'virtual'})
#             wrapped()
#             # test via host based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.create_external_boto_client('s3', config={'addressing_style': 'path'})
#             wrapped()
#         finally:
#             # reset client
#             TestS3.OVERWRITTEN_CLIENT = None
#     return


class TestS3(unittest.TestCase):
    OVERWRITTEN_CLIENT = None

    def setUp(self):
        # Default S3 operations should be happening in us-east-1, hence passing in the region
        # here (otherwise create_bucket(..) would fail without specifying a location constraint.
        # Dedicated multi-region tests use specific clients further below.
        self._s3_client = aws_stack.create_external_boto_client(
            "s3", region_name=AWS_REGION_US_EAST_1
        )
        self.sqs_client = aws_stack.create_external_boto_client("sqs")

    @property
    def s3_client(self):
        return TestS3.OVERWRITTEN_CLIENT or self._s3_client

    # TODO
    # Note: This test may have side effects (via `s3_client.meta.events.register(..)`) and
    # may not be suitable for parallel execution
    def test_presign_with_query_params(self):
        def add_query_param(self, request, **kwargs):
            request.url += "requestedBy=abcDEF123"

        bucket_name = short_uid()
        s3_client = aws_stack.create_external_boto_client("s3")
        s3_presign = boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=Config(signature_version="s3v4"),
        )

        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_object(Body="test-value", Bucket=bucket_name, Key="test")
        response = s3_client.head_object(Bucket=bucket_name, Key="test")
        s3_client.meta.events.register("before-sign.s3.GetObject", add_query_param)
        try:
            presign_url = s3_presign.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket_name, "Key": "test"},
                ExpiresIn=86400,
            )
            response = requests.get(presign_url)
            self.assertEqual(b"test-value", response._content)
        finally:
            s3_client.meta.events.unregister("before-sign.s3.GetObject", add_query_param)

    # TODO
    @pytest.mark.skip_offline
    def test_s3_lambda_integration(self):
        if not use_docker():
            return
        temp_folder = new_tmp_dir()
        handler_file = os.path.join(
            THIS_FOLDER, "awslambda", "functions", "lambda_s3_integration.js"
        )
        shutil.copy(handler_file, temp_folder)
        run("cd %s; npm i @aws-sdk/client-s3; npm i @aws-sdk/s3-request-presigner" % temp_folder)

        function_name = "func-integration-%s" % short_uid()
        lambda_client = aws_stack.create_external_boto_client("lambda")
        s3_client = aws_stack.create_external_boto_client("s3")

        testutil.create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(temp_folder, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS14X,
            handler="lambda_s3_integration.handler",
        )
        s3_client.create_bucket(Bucket=function_name)

        response = lambda_client.invoke(FunctionName=function_name)
        presigned_url = response["Payload"].read()
        presigned_url = json.loads(to_str(presigned_url))["body"].strip('"')

        response = requests.put(presigned_url, verify=False)
        response = s3_client.head_object(Bucket=function_name, Key="key.png")
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        s3_client.delete_object(Bucket=function_name, Key="key.png")
        s3_client.delete_bucket(Bucket=function_name)

    # TODO -> not sure if this test makes sense in the future..
    def test_presign_port_permutation(self):
        bucket_name = short_uid()
        port1 = 443
        port2 = 4566
        s3_client = aws_stack.create_external_boto_client("s3")

        s3_presign = boto3.client(
            "s3",
            endpoint_url="http://127.0.0.1:%s" % port1,
            aws_access_key_id="test",
            aws_secret_access_key="test",
            config=Config(signature_version="s3v4"),
        )

        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_object(Body="test-value", Bucket=bucket_name, Key="test")
        response = s3_client.head_object(Bucket=bucket_name, Key="test")

        presign_url = s3_presign.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket_name, "Key": "test"},
            ExpiresIn=86400,
        )
        presign_url = presign_url.replace(":%s" % port1, ":%s" % port2)

        response = requests.get(presign_url)
        self.assertEqual(b"test-value", response._content)

    # ---------------
    # HELPER METHODS
    # ---------------

    def _delete_bucket(self, bucket_name, keys=None):
        if keys is None:
            keys = []
        keys = keys if isinstance(keys, list) else [keys]
        objects = [{"Key": k} for k in keys]
        if objects:
            self.s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def _perform_multipart_upload(self, bucket, key, data=None, zip=False, acl=None):
        kwargs = {"ACL": acl} if acl else {}
        multipart_upload_dict = self.s3_client.create_multipart_upload(
            Bucket=bucket, Key=key, **kwargs
        )
        upload_id = multipart_upload_dict["UploadId"]

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zip:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode="w") as filestream:
                filestream.write(data)

        response = self.s3_client.upload_part(
            Bucket=bucket,
            Key=key,
            Body=upload_file_object,
            PartNumber=1,
            UploadId=upload_id,
        )

        multipart_upload_parts = [{"ETag": response["ETag"], "PartNumber": 1}]

        return self.s3_client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            MultipartUpload={"Parts": multipart_upload_parts},
            UploadId=upload_id,
        )

    def _get_test_client(self, region_name="us-east-1"):
        return boto3.client(
            "s3",
            endpoint_url=config.get_edge_url(),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            region_name=region_name,
        )


# TODO
@pytest.mark.only_localstack
def test_put_object_with_md5_and_chunk_signature(s3_client):
    # can't make it work with AWS_CLOUD
    # based on https://github.com/localstack/localstack/issues/4987
    bucket_name = "bucket-%s" % short_uid()
    object_key = "test-runtime.properties"
    object_data = (
        "#20211122+0100\n"
        "#Mon Nov 22 20:10:44 CET 2021\n"
        "last.sync.url.test-space-key=2822a50f-4992-425a-b8fb-923735a9ddff317e3479-5907-46cf-b33a-60da9709274f\n"
    )
    object_data_chunked = (
        "93;chunk-signature=5be6b2d473e96bb9f297444da60bdf0ff8f5d2e211e1d551b3cf3646c0946641\r\n"
        "%s"
        "\r\n0;chunk-signature=bd5c830b94346b57ddc8805ba26c44a122256c207014433bf6579b0985f21df7\r\n\r\n"
        % object_data
    )
    content_md5 = base64.b64encode(hashlib.md5(object_data.encode()).digest()).decode()
    headers = {
        "Content-Md5": content_md5,
        "Content-Type": "application/octet-stream",
        "User-Agent": (
            "aws-sdk-java/1.11.951 Mac_OS_X/10.15.7 OpenJDK_64-Bit_Server_VM/11.0.11+9-LTS "
            "java/11.0.11 scala/2.13.6 kotlin/1.5.31 vendor/Amazon.com_Inc."
        ),
        "X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "X-Amz-Date": "20211122T191045Z",
        "X-Amz-Decoded-Content-Length": str(len(object_data)),
        "Content-Length": str(len(object_data_chunked)),
        "Connection": "Keep-Alive",
        "Expect": "100-continue",
    }

    s3_client.create_bucket(Bucket=bucket_name)
    url = s3_client.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket_name,
            "Key": object_key,
            "ContentType": "application/octet-stream",
            "ContentMD5": content_md5,
        },
    )
    result = requests.put(url, data=object_data_chunked, headers=headers)
    assert result.status_code == 200, (result, result.content)
