# TODO: migrate tests to tests/integration/s3/
#  DO NOT ADD ADDITIONAL TESTS HERE. USE PYTEST AND RUN TESTS AGAINST AWS!
import unittest
from urllib.request import Request

import boto3
import requests
from botocore.client import Config

from localstack import config
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


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
