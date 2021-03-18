import io
import os
import ssl
import boto3
import gzip
import json
import time
import uuid
import unittest
import datetime
import requests
from io import BytesIO
from pytz import timezone
from urllib.parse import parse_qs, quote
from botocore.exceptions import ClientError
from six.moves.urllib import parse as urlparse
from six.moves.urllib.request import Request, urlopen
from localstack import config, constants
from botocore.client import Config
from localstack.utils import testutil
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY, S3_VIRTUAL_HOSTNAME
from localstack.utils.aws import aws_stack
from localstack.services.s3 import s3_listener, s3_utils

from localstack.utils.common import (
    short_uid, retry, get_service_protocol, to_bytes, safe_requests, to_str, new_tmp_file, rm_rf, load_file)
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36

TEST_BUCKET_NAME_WITH_POLICY = 'test-bucket-policy-1'
TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION = 'test_queue_for_bucket_notification_1'
TEST_BUCKET_WITH_VERSIONING = 'test-bucket-versioning-1'

TEST_BUCKET_NAME_2 = 'test-bucket-2'
TEST_KEY_2 = 'test-key-2'
TEST_GET_OBJECT_RANGE = 17

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_triggered_by_s3.py')
TEST_LAMBDA_PYTHON_DOWNLOAD_FROM_S3 = os.path.join(THIS_FOLDER, 'lambdas',
                                                   'lambda_triggered_by_sqs_download_s3_file.py')

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
    """ Class to handle putting with urllib """
    def __init__(self, *args, **kwargs):
        return Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return 'PUT'


# def test_host_and_path_addressing(wrapped):
#     """ Decorator that runs a test method with both - path and host style addressing. """
#     # TODO - needs to be fixed below!
#     def wrapper(self):
#         try:
#             # test via path based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.connect_to_service('s3', config={'addressing_style': 'virtual'})
#             wrapped()
#             # test via host based addressing
#             TestS3.OVERWRITTEN_CLIENT = aws_stack.connect_to_service('s3', config={'addressing_style': 'path'})
#             wrapped()
#         finally:
#             # reset client
#             TestS3.OVERWRITTEN_CLIENT = None
#     return

class TestS3(unittest.TestCase):
    OVERWRITTEN_CLIENT = None

    def setUp(self):
        self._s3_client = aws_stack.connect_to_service('s3')
        self.sqs_client = aws_stack.connect_to_service('sqs')

    @property
    def s3_client(self):
        return TestS3.OVERWRITTEN_CLIENT or self._s3_client

    def test_create_bucket_via_host_name(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
            <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <LocationConstraint>eu-central-1</LocationConstraint>
            </CreateBucketConfiguration>"""
        headers = aws_stack.mock_aws_request_headers('s3')
        bucket_name = 'test-%s' % short_uid()
        headers['Host'] = s3_utils.get_bucket_hostname(bucket_name)
        response = requests.put(config.TEST_S3_URL, data=body, headers=headers, verify=False)
        self.assertEquals(response.status_code, 200)
        response = self.s3_client.get_bucket_location(Bucket=bucket_name)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('LocationConstraint', response)

    # @test_host_and_path_addressing
    def test_bucket_policy(self):
        # create test bucket
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_POLICY)

        # put bucket policy
        policy = {
            'Version': '2012-10-17',
            'Statement': {
                'Action': ['s3:GetObject'],
                'Effect': 'Allow',
                'Resource': 'arn:aws:s3:::bucketName/*',
                'Principal': {
                    'AWS': ['*']
                }
            }
        }
        response = self.s3_client.put_bucket_policy(
            Bucket=TEST_BUCKET_NAME_WITH_POLICY,
            Policy=json.dumps(policy)
        )
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 204)

        # retrieve and check policy config
        saved_policy = self.s3_client.get_bucket_policy(Bucket=TEST_BUCKET_NAME_WITH_POLICY)['Policy']
        self.assertEqual(json.loads(saved_policy), policy)

    def test_s3_put_object_notification(self):
        bucket_name = 'notif-%s' % short_uid()
        key_by_path = 'key-by-hostname'
        key_by_host = 'key-by-host'
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)
        self.s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Enabled'})

        # put an object where the bucket_name is in the path
        obj = self.s3_client.put_object(Bucket=bucket_name, Key=key_by_path, Body='something')

        # put an object where the bucket_name is in the host
        headers = aws_stack.mock_aws_request_headers('s3')
        headers['Host'] = s3_utils.get_bucket_hostname(bucket_name)
        url = '{}/{}'.format(config.TEST_S3_URL, key_by_host)
        # verify=False must be set as this test fails on travis because of an SSL error non-existent locally
        response = requests.put(url, data='something else', headers=headers, verify=False)
        self.assertTrue(response.ok)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '2')

        response = self.sqs_client.receive_message(QueueUrl=queue_url)
        messages = [json.loads(to_str(m['Body'])) for m in response['Messages']]
        record = messages[0]['Records'][0]
        self.assertIsNotNone(record['s3']['object']['versionId'])
        self.assertEquals(record['s3']['object']['versionId'], obj['VersionId'])

        # clean up
        self.s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Disabled'})
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(bucket_name, [key_by_path, key_by_host])

    def test_s3_upload_fileobj_with_large_file_notification(self):
        bucket_name = 'notif-large-%s' % short_uid()
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)

        # has to be larger than 64MB to be broken up into a multipart upload
        file_size = 75000000
        large_file = self.generate_large_file(file_size)
        download_file = new_tmp_file()
        try:
            self.s3_client.upload_file(Bucket=bucket_name, Key=large_file.name, Filename=large_file.name)

            self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

            # ensure that the first message's eventName is ObjectCreated:CompleteMultipartUpload
            messages = self.sqs_client.receive_message(QueueUrl=queue_url, AttributeNames=['All'])
            message = json.loads(messages['Messages'][0]['Body'])
            self.assertEqual(message['Records'][0]['eventName'], 'ObjectCreated:CompleteMultipartUpload')

            # download the file, check file size
            self.s3_client.download_file(Bucket=bucket_name, Key=large_file.name, Filename=download_file)
            self.assertEqual(os.path.getsize(download_file), file_size)

            # clean up
            self.sqs_client.delete_queue(QueueUrl=queue_url)
            self._delete_bucket(bucket_name, large_file.name)
        finally:
            # clean up large files
            large_file.close()
            rm_rf(large_file.name)
            rm_rf(download_file)

    def test_s3_multipart_upload_with_small_single_part(self):
        # In a multipart upload "Each part must be at least 5 MB in size, except the last part."
        # https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadComplete.html

        bucket_name = 'notif-large-%s' % short_uid()
        key_by_path = 'key-by-hostname'
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)

        # perform upload
        self._perform_multipart_upload(bucket=bucket_name, key=key_by_path, zip=True)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(bucket_name, [key_by_path])

    def test_invalid_range_error(self):
        bucket_name = 'range-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key='steve', Body=b'is awesome')

        try:
            self.s3_client.get_object(Bucket=bucket_name, Key='steve', Range='bytes=1024-4096')
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidRange')

        # clean up
        self._delete_bucket(bucket_name, ['steve'])

    def test_range_key_not_exists(self):
        bucket_name = 'range-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        self.s3_client.create_bucket(Bucket=bucket_name)
        with self.assertRaises(ClientError) as ctx:
            self.s3_client.get_object(Bucket=bucket_name, Key='key', Range='bytes=1024-4096')

        self.assertIn('NoSuchKey', str(ctx.exception))

        # clean up
        self._delete_bucket(bucket_name)

    def test_upload_key_with_hash_prefix(self):
        bucket_name = 'hash-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        key_name = '#key-with-hash-prefix'
        content = b'test 123'
        self.s3_client.put_object(Bucket=bucket_name, Key=key_name, Body=content)

        downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=key_name)
        downloaded_content = to_str(downloaded_object['Body'].read())
        self.assertEqual(to_str(downloaded_content), to_str(content))

        # clean up
        self._delete_bucket(bucket_name, [key_name])
        with self.assertRaises(Exception):
            self.s3_client.head_object(Bucket=bucket_name, Key=key_name)

    def test_s3_multipart_upload_acls(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name, ACL='public-read')

        def check_permissions(key, expected_perms):
            grants = self.s3_client.get_object_acl(Bucket=bucket_name, Key=key)['Grants']
            grants = [g for g in grants if 'AllUsers' in g.get('Grantee', {}).get('URI', '')]
            self.assertEquals(len(grants), 1)
            permissions = grants[0]['Permission']
            permissions = permissions if isinstance(permissions, list) else [permissions]
            self.assertEquals(len(permissions), expected_perms)

        # perform uploads (multipart and regular) and check ACLs
        self.s3_client.put_object(Bucket=bucket_name, Key='acl-key0', Body='something')
        check_permissions('acl-key0', 1)
        self._perform_multipart_upload(bucket=bucket_name, key='acl-key1')
        check_permissions('acl-key1', 1)
        self._perform_multipart_upload(bucket=bucket_name, key='acl-key2', acl='public-read-write')
        check_permissions('acl-key2', 2)

    def test_s3_presigned_url_upload(self):
        key_by_path = 'key-by-hostname'
        bucket_name = 'notif-large-%s' % short_uid()
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)

        self._perform_presigned_url_upload(bucket=bucket_name, key=key_by_path)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(bucket_name, [key_by_path])

    def test_s3_get_response_default_content_type(self):
        # When no content type is provided by a PUT request
        # 'binary/octet-stream' should be used
        # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html

        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        url = client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key})

        # get object and assert headers
        response = requests.get(url, verify=False)
        self.assertEqual(response.headers['content-type'], 'binary/octet-stream')
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_put_presigned_url_metadata(self):
        # Object metadata should be passed as query params via presigned URL
        # https://github.com/localstack/localstack/issues/544
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        metadata = {
            'foo': 'bar'
        }

        # put object
        object_key = 'key-by-hostname'
        url = client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket_name, 'Key': object_key, 'Metadata': metadata})
        # append metadata manually to URL (this is not easily possible with boto3, as "Metadata" cannot
        # be passed to generate_presigned_url, and generate_presigned_post works differently)

        # get object and assert metadata is present
        response = requests.put(url, data='content 123', verify=False)
        self.assertLess(response.status_code, 400)
        # response body should be empty, see https://github.com/localstack/localstack/issues/1317
        self.assertEqual('', to_str(response.content))
        response = client.head_object(Bucket=bucket_name, Key=object_key)
        self.assertEquals('bar', response.get('Metadata', {}).get('foo'))

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_put_metadata_underscores(self):
        # Object metadata keys should accept keys with underscores
        # https://github.com/localstack/localstack/issues/1790
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-with-metadata'
        metadata = {'test_meta_1': 'foo', '__meta_2': 'bar'}
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Metadata=metadata, Body='foo')
        metadata_saved = self.s3_client.head_object(Bucket=bucket_name, Key=object_key)['Metadata']
        self.assertEqual(metadata, metadata_saved)

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_object_expiry(self):
        # handle s3 object expiry
        # https://github.com/localstack/localstack/issues/1685
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-with-metadata'
        metadata = {'test_meta_1': 'foo', '__meta_2': 'bar'}
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Metadata=metadata, Body='foo',
                                  Expires=datetime.datetime.now(timezone('GMT')) - datetime.timedelta(hours=1))
        # try to fetch an object which is already expired
        self.assertRaises(Exception, self.s3_client.get_object, Bucket=bucket_name, Key=object_key.lower())

        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Metadata=metadata, Body='foo',
                                  Expires=datetime.datetime.now(timezone('GMT')) + datetime.timedelta(hours=1))

        # try to fetch has not been expired yet.
        resp = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)

        self.assertIn('Expires', resp)

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_presigned_url_expired(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object and CORS configuration
        object_key = 'key-by-hostname'
        client.put_object(Bucket=bucket_name, Key=object_key, Body='something')

        # get object and assert headers
        url = client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key}, ExpiresIn=2
        )
        # retrieving it before expiry
        resp = requests.get(url, verify=False)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(to_str(resp.content), 'something')

        # waiting for the url to expire
        time.sleep(3)
        resp = requests.get(url, verify=False)
        self.assertEqual(resp.status_code, 403)

        url = client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key}, ExpiresIn=120
        )

        resp = requests.get(url, verify=False)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(to_str(resp.content), 'something')

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_bucket_availability(self):
        bucket_name = 'test-bucket-lifecycle'
        returned_empty_lifecycle = s3_listener.get_lifecycle(bucket_name)
        self.assertRegexpMatches(returned_empty_lifecycle._content, r'The bucket does not exist')

        response = s3_listener.get_replication(bucket_name)
        self.assertRegexpMatches(response._content, r'The bucket does not exist')

        response = s3_listener.get_encryption(bucket_name)
        self.assertRegexpMatches(response._content, r'The bucket does not exist')

        response = s3_listener.get_object_lock(bucket_name)
        self.assertRegexpMatches(response._content, r'The bucket does not exist')

    def test_delete_bucket_lifecycle_configuration(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        lfc = {
            'Rules': [
                {
                    'Expiration': {'Days': 7},
                    'ID': 'wholebucket',
                    'Filter': {'Prefix': ''},
                    'Status': 'Enabled',
                }
            ]
        }
        client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name, LifecycleConfiguration=lfc
        )
        result = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        self.assertIn('Rules', result)
        client.delete_bucket_lifecycle(Bucket=bucket_name)

        try:
            client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchLifecycleConfiguration')

        # clean up
        client.delete_bucket(Bucket=bucket_name)

    def test_delete_lifecycle_configuration_on_bucket_deletion(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        lfc = {
            'Rules': [
                {
                    'Expiration': {'Days': 7},
                    'ID': 'wholebucket',
                    'Filter': {'Prefix': ''},
                    'Status': 'Enabled',
                }
            ]
        }
        client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name, LifecycleConfiguration=lfc
        )
        result = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        self.assertIn('Rules', result)

        client.delete_bucket(Bucket=bucket_name)

        client.create_bucket(Bucket=bucket_name)
        try:
            client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchLifecycleConfiguration')

        # clean up
        client.delete_bucket(Bucket=bucket_name)

    def test_range_header_body_length(self):
        # Test for https://github.com/localstack/localstack/issues/1952

        object_key = 'sample.bin'
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            self.s3_client.upload_fileobj(data, bucket_name, object_key)

        range_header = 'bytes=0-%s' % (chunk_size - 1)
        resp = self.s3_client.get_object(Bucket=bucket_name, Key=object_key, Range=range_header)
        content = resp['Body'].read()
        self.assertEquals(len(content), chunk_size)

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_get_response_content_type_same_as_upload_and_range(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'foo/bar/key-by-hostname'
        content_type = 'foo/bar; charset=utf-8'
        client.put_object(Bucket=bucket_name,
            Key=object_key,
            Body='something ' * 20,
            ContentType=content_type)

        url = client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )

        # get object and assert headers
        response = requests.get(url, verify=False)
        self.assertEqual(response.headers['content-type'], content_type)

        # get object using range query and assert headers
        response = requests.get(url, headers={'Range': 'bytes=0-18'}, verify=False)
        self.assertEqual(response.headers['content-type'], content_type)
        self.assertEqual(to_str(response.content), 'something something')

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_get_get_object_headers(self):
        object_key = 'sample.bin'
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        chunk_size = 1024

        with io.BytesIO() as data:
            data.write(os.urandom(chunk_size * 2))
            data.seek(0)
            self.s3_client.upload_fileobj(data, bucket_name, object_key)

        range_header = 'bytes=0-%s' % (chunk_size - 1)
        resp = self.s3_client.get_object(Bucket=bucket_name, Key=object_key, Range=range_header)
        self.assertEqual(resp.get('AcceptRanges'), 'bytes')
        self.assertIn('x-amz-request-id', resp['ResponseMetadata']['HTTPHeaders'])
        self.assertIn('x-amz-id-2', resp['ResponseMetadata']['HTTPHeaders'])
        self.assertIn('content-language', resp['ResponseMetadata']['HTTPHeaders'])
        self.assertIn('cache-control', resp['ResponseMetadata']['HTTPHeaders'])
        self.assertIn('content-encoding', resp['ResponseMetadata']['HTTPHeaders'])

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_head_response_content_length_same_as_upload(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        body = 'something body \n \n\r'
        # put object
        object_key = 'key-by-hostname'
        client.put_object(Bucket=bucket_name, Key=object_key, Body=body, ContentType='text/html; charset=utf-8')
        url = client.generate_presigned_url(
            'head_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )
        # get object and assert headers
        response = requests.head(url, verify=False)
        self.assertEqual(response.headers['content-length'], str(len(body)))
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_put_object_chunked_newlines(self):
        # Test for https://github.com/localstack/localstack/issues/1571
        bucket_name = 'test-bucket-%s' % short_uid()
        object_key = 'data'
        self.s3_client.create_bucket(Bucket=bucket_name)
        body = 'Hello\r\n\r\n\r\n\r\n'
        headers = """
            Authorization: %s
            Content-Type: audio/mpeg
            X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
            X-Amz-Date: 20190918T051509Z
            X-Amz-Decoded-Content-Length: %s
        """ % (aws_stack.mock_aws_request_headers('s3')['Authorization'], len(body))
        headers = dict([[field.strip() for field in pair.strip().split(':', 1)]
            for pair in headers.strip().split('\n')])
        data = ('d;chunk-signature=af5e6c0a698b0192e9aa5d9083553d4d241d81f69ec62b184d05c509ad5166af\r\n' +
            '%s\r\n0;chunk-signature=f2a50a8c0ad4d212b579c2489c6d122db88d8a0d0b987ea1f3e9d081074a5937\r\n') % body
        # put object
        url = '%s/%s/%s' % (config.TEST_S3_URL, bucket_name, object_key)
        req = PutRequest(url, to_bytes(data), headers)
        urlopen(req, context=ssl.SSLContext()).read()
        # get object and assert content length
        downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        download_file_object = to_str(downloaded_object['Body'].read())
        self.assertEqual(len(str(download_file_object)), len(body))
        self.assertEqual(str(download_file_object), body)
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_put_object_on_presigned_url(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        body = 'something body'
        # get presigned URL
        object_key = 'test-presigned-key'
        url = client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )
        # put object
        response = requests.put(url, data=body, verify=False)
        self.assertEqual(response.status_code, 200)
        # get object and compare results
        downloaded_object = client.get_object(Bucket=bucket_name, Key=object_key)
        download_object = downloaded_object['Body'].read()
        self.assertEqual(to_str(body), to_str(download_object))
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_post_object_on_presigned_post(self):
        bucket_name = 'test-presigned-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        body = 'something body'
        # get presigned URL
        object_key = 'test-presigned-post-key'
        presigned_request = client.generate_presigned_post(
            Bucket=bucket_name, Key=object_key, ExpiresIn=60)
        # put object
        files = {'file': body}
        response = requests.post(presigned_request['url'], data=presigned_request['fields'], files=files, verify=False)
        self.assertIn(response.status_code, [200, 204])
        # get object and compare results
        downloaded_object = client.get_object(Bucket=bucket_name, Key=object_key)
        download_object = downloaded_object['Body'].read()
        self.assertEqual(to_str(body), to_str(download_object))
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_presigned_post_success_action_status_201_response(self):
        bucket_name = 'test-presigned-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)
        body = 'something body'
        # get presigned URL
        object_key = 'key-${filename}'
        presigned_request = client.generate_presigned_post(
            Bucket=bucket_name,
            Key=object_key,
            Fields={'success_action_status': 201},
            ExpiresIn=60
        )
        files = {'file': ('my-file', body)}
        response = requests.post(presigned_request['url'], data=presigned_request['fields'], files=files, verify=False)
        # test
        expected_response_content = """
                <PostResponse>
                    <Location>{location}</Location>
                    <Bucket>{bucket}</Bucket>
                    <Key>{key}</Key>
                    <ETag>{etag}</ETag>
                </PostResponse>
                """.format(
            location='http://localhost/key-my-file',
            bucket=bucket_name,
            key='key-my-file',
            etag='d41d8cd98f00b204e9800998ecf8427f'
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.text, expected_response_content)
        # clean up
        self._delete_bucket(bucket_name, ['key-my-file'])

    def test_s3_presigned_post_expires(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # presign a post with a short expiry time
        object_key = 'test-presigned-post-key'
        presigned_request = client.generate_presigned_post(
            Bucket=bucket_name,
            Key=object_key,
            ExpiresIn=2
        )

        # sleep so it expires
        time.sleep(3)

        # attempt to use the presigned request
        files = {'file': 'file content'}
        response = requests.post(presigned_request['url'], data=presigned_request['fields'], files=files, verify=False)

        self.assertEqual(response.status_code, 400)
        self.assertTrue('ExpiredToken' in response.text)

        # clean up
        self._delete_bucket(bucket_name)

    def test_s3_delete_response_content_length_zero(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        for encoding in None, 'gzip':
            # put object
            object_key = 'key-by-hostname'
            client.put_object(Bucket=bucket_name,
                Key=object_key,
                Body='something',
                ContentType='text/html; charset=utf-8')
            url = client.generate_presigned_url(
                'delete_object',
                Params={'Bucket': bucket_name, 'Key': object_key}
            )

            # get object and assert headers
            headers = {}
            if encoding:
                headers['Accept-Encoding'] = encoding
            response = requests.delete(url, headers=headers, verify=False)

            self.assertEqual(response.headers['content-length'],
                '0',
                f'Unexpected response Content-Length for encoding {encoding}')

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_delete_object_tagging(self):
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name, ACL='public-read')
        object_key = 'test-key-tagging'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        # get object and assert response
        url = '%s/%s/%s' % (config.TEST_S3_URL, bucket_name, object_key)
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 200)
        # delete object tagging
        self.s3_client.delete_object_tagging(Bucket=bucket_name, Key=object_key)
        # assert that the object still exists
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 200)
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_delete_non_existing_keys(self):
        bucket_name = 'test-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        object_key = 'test-key-nonexistent'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        response = self.s3_client.delete_objects(Bucket=bucket_name,
            Delete={'Objects': [{'Key': object_key}, {'Key': 'dummy1'}, {'Key': 'dummy2'}]})
        self.assertEqual(len(response['Deleted']), 3)
        self.assertNotIn('Errors', response)
        # clean up
        self._delete_bucket(bucket_name)

    def test_bucket_exists(self):
        # Test setup
        bucket = 'test-bucket-%s' % short_uid()

        s3_client = aws_stack.connect_to_service('s3')
        s3_client.create_bucket(Bucket=bucket)
        s3_client.put_bucket_cors(
            Bucket=bucket,
            CORSConfiguration={
                'CORSRules': [{'AllowedMethods': ['GET', 'POST', 'PUT', 'DELETE'],
                               'AllowedOrigins': ['localhost']}]
            }
        )

        response = s3_client.get_bucket_cors(Bucket=bucket)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # Cleanup
        s3_client.delete_bucket(Bucket=bucket)

    def test_s3_uppercase_key_names(self):
        # bucket name should be case-sensitive
        bucket_name = 'testuppercase-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # key name should be case-sensitive
        object_key = 'camelCaseKey'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        res = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        self.assertEqual(res['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_s3_get_response_headers(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object and CORS configuration
        object_key = 'key-by-hostname'
        client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        client.put_bucket_cors(Bucket=bucket_name,
            CORSConfiguration={
                'CORSRules': [{
                    'AllowedMethods': ['GET', 'PUT', 'POST'],
                    'AllowedOrigins': ['*'],
                    'ExposeHeaders': [
                        'ETag', 'x-amz-version-id'
                    ]
                }]
            },
        )

        # get object and assert headers
        url = client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )
        response = requests.get(url, verify=False)
        self.assertEquals(response.headers['Access-Control-Expose-Headers'], 'ETag,x-amz-version-id')
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_get_response_header_overrides(self):
        # Signed requests may include certain header overrides in the querystring
        # https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html

        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        client.put_object(Bucket=bucket_name, Key=object_key, Body='something')

        # get object and assert headers
        expiry_date = 'Wed, 21 Oct 2015 07:28:00 GMT'
        url = client.generate_presigned_url(
            'get_object', Params={
                'Bucket': bucket_name,
                'Key': object_key,
                'ResponseCacheControl': 'max-age=74',
                'ResponseContentDisposition': 'attachment; filename="foo.jpg"',
                'ResponseContentEncoding': 'identity',
                'ResponseContentLanguage': 'de-DE',
                'ResponseContentType': 'image/jpeg',
                'ResponseExpires': expiry_date}
        )
        response = requests.get(url, verify=False)

        self.assertEqual(response.headers['cache-control'], 'max-age=74')
        self.assertEqual(response.headers['content-disposition'], 'attachment; filename="foo.jpg"')
        self.assertEqual(response.headers['content-encoding'], 'identity')
        self.assertEqual(response.headers['content-language'], 'de-DE')
        self.assertEqual(response.headers['content-type'], 'image/jpeg')
        # Note: looks like depending on the environment/libraries, we can get different date formats...
        possible_date_formats = ['2015-10-21T07:28:00Z', expiry_date]
        self.assertIn(response.headers['expires'], possible_date_formats)
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_copy_md5(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        client = self._get_test_client()
        client.create_bucket(Bucket=bucket_name)

        # put object
        src_key = 'src'
        client.put_object(Bucket=bucket_name, Key=src_key, Body='something')

        # copy object
        dest_key = 'dest'
        response = client.copy_object(
            Bucket=bucket_name,
            CopySource={
                'Bucket': bucket_name,
                'Key': src_key
            },
            Key=dest_key
        )
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # Create copy object to try to match s3a setting Content-MD5
        dest_key2 = 'dest'
        url = client.generate_presigned_url(
            'copy_object', Params={'Bucket': bucket_name, 'CopySource': {'Bucket': bucket_name, 'Key': src_key},
                                   'Key': dest_key2}
        )

        request_response = requests.put(url, verify=False)
        self.assertEqual(request_response.status_code, 200)

        # Cleanup
        self._delete_bucket(bucket_name, [src_key, dest_key, dest_key2])

    def test_s3_invalid_content_md5(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object with invalid content MD5
        hashes = {
            '__invalid__': 'InvalidDigest',
            '000': 'InvalidDigest',
            'not base64 encoded checksum': 'InvalidDigest',  # InvalidDigest
            'MTIz': 'BadDigest'  # "123" base64 encoded
        }
        for hash, error in hashes.items():
            with self.assertRaises(Exception) as ctx:
                self.s3_client.put_object(Bucket=bucket_name, Key='test-key',
                    Body='something', ContentMD5=hash)
            self.assertIn(error, str(ctx.exception))

        # Cleanup
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_s3_upload_download_gzip(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        data = '1234567890 ' * 100

        # Write contents to memory rather than a file.
        upload_file_object = BytesIO()
        with gzip.GzipFile(fileobj=upload_file_object, mode='w') as filestream:
            filestream.write(data.encode('utf-8'))

        # Upload gzip
        self.s3_client.put_object(Bucket=bucket_name, Key='test.gz',
            ContentEncoding='gzip', Body=upload_file_object.getvalue())

        # Download gzip
        downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key='test.gz')
        download_file_object = BytesIO(downloaded_object['Body'].read())
        with gzip.GzipFile(fileobj=download_file_object, mode='rb') as filestream:
            downloaded_data = filestream.read().decode('utf-8')

        self.assertEqual(downloaded_data, data)

    def test_set_external_hostname(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        key = 'test.file'
        hostname_before = config.HOSTNAME_EXTERNAL
        config.HOSTNAME_EXTERNAL = 'foobar'
        try:
            content = 'test content 123'
            acl = 'public-read'
            self.s3_client.create_bucket(Bucket=bucket_name)
            # upload file
            response = self._perform_multipart_upload(bucket=bucket_name, key=key, data=content, acl=acl)
            expected_url = '%s://%s:%s/%s/%s' % (get_service_protocol(), config.HOSTNAME_EXTERNAL,
                config.PORT_S3, bucket_name, key)
            self.assertEqual(expected_url, response['Location'])
            # fix object ACL - currently not directly support for multipart uploads
            self.s3_client.put_object_acl(Bucket=bucket_name, Key=key, ACL=acl)
            # download object via API
            downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            self.assertEqual(to_str(downloaded_object['Body'].read()), content)
            # download object directly from download link
            download_url = response['Location'].replace('%s:' % config.HOSTNAME_EXTERNAL, 'localhost:')
            response = safe_requests.get(download_url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(to_str(response.content), content)
        finally:
            config.HOSTNAME_EXTERNAL = hostname_before

    def test_s3_static_website_hosting(self):
        bucket_name = 'test-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key='test/index.html', Body='index')
        self.s3_client.put_object(Bucket=bucket_name, Key='test/error.html', Body='error')
        self.s3_client.put_object(Bucket=bucket_name, Key='actual/key.html', Body='key')
        self.s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={'IndexDocument': {'Suffix': 'index.html'},
                'ErrorDocument': {'Key': 'test/error.html'}}
        )

        headers = aws_stack.mock_aws_request_headers('s3')
        headers['Host'] = s3_utils.get_bucket_website_hostname(bucket_name)

        # actual key
        url = 'https://{}.{}:{}/actual/key.html'.format(bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME,
            config.EDGE_PORT)
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, 'key')

        # index document
        url = 'https://{}.{}:{}/test'.format(bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT)
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.text, 'index')

        # root path test
        url = 'https://{}.{}:{}/'.format(bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT)
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.text, 'error')

        # error document
        url = 'https://{}.{}:{}/something'.format(bucket_name, constants.S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT)
        response = requests.get(url, headers=headers, verify=False)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.text, 'error')

    def test_s3_event_notification_with_sqs(self):
        key_by_path = 'aws/bucket=2020/test1.txt'
        bucket_name = 'notif-sqs-%s' % short_uid()

        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)
        self.s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Enabled'})

        body = 'Lorem ipsum dolor sit amet, ... ' * 30

        # put an object
        self.s3_client.put_object(Bucket=bucket_name, Key=key_by_path, Body=body)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        rs = self.sqs_client.receive_message(QueueUrl=queue_url)
        record = [json.loads(to_str(m['Body'])) for m in rs['Messages']][0]['Records'][0]

        download_file = new_tmp_file()
        self.s3_client.download_file(Bucket=bucket_name, Key=key_by_path, Filename=download_file)

        self.assertEqual(record['s3']['object']['size'], os.path.getsize(download_file))

        # clean up
        self.s3_client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Disabled'})
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(bucket_name, [key_by_path])

    def test_s3_delete_object_with_version_id(self):
        test_1st_key = 'aws/s3/testkey1.txt'
        test_2nd_key = 'aws/s3/testkey2.txt'

        body = 'Lorem ipsum dolor sit amet, ... ' * 30

        self.s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_VERSIONING,
                                             VersioningConfiguration={'Status': 'Enabled'})

        # put 2 objects
        rs = self.s3_client.put_object(Bucket=TEST_BUCKET_WITH_VERSIONING, Key=test_1st_key, Body=body)
        self.s3_client.put_object(Bucket=TEST_BUCKET_WITH_VERSIONING, Key=test_2nd_key, Body=body)

        version_id = rs['VersionId']

        # delete 1st object with version
        rs = self.s3_client.delete_objects(Bucket=TEST_BUCKET_WITH_VERSIONING,
                                           Delete={'Objects': [{'Key': test_1st_key, 'VersionId': version_id}]})

        deleted = rs['Deleted'][0]
        self.assertEqual(deleted['Key'], test_1st_key)
        self.assertEqual(deleted['VersionId'], version_id)

        rs = self.s3_client.list_object_versions(Bucket=TEST_BUCKET_WITH_VERSIONING)
        object_versions = [object['VersionId'] for object in rs['Versions']]

        self.assertNotIn(version_id, object_versions)

        # clean up
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_VERSIONING,
                                             VersioningConfiguration={'Status': 'Disabled'})
        self._delete_bucket(TEST_BUCKET_WITH_VERSIONING, [test_1st_key, test_2nd_key])

    def test_etag_on_get_object_call(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_NAME_2)

        body = 'Lorem ipsum dolor sit amet, ... ' * 30
        rs = self.s3_client.put_object(Bucket=TEST_BUCKET_NAME_2, Key=TEST_KEY_2, Body=body)
        etag = rs['ETag']

        rs = self.s3_client.get_object(
            Bucket=TEST_BUCKET_NAME_2,
            Key=TEST_KEY_2
        )
        self.assertIn('ETag', rs)
        self.assertEqual(etag, rs['ETag'])
        self.assertEqual(rs['ContentLength'], len(body))

        rs = self.s3_client.get_object(
            Bucket=TEST_BUCKET_NAME_2,
            Key=TEST_KEY_2,
            Range='bytes=0-{}'.format(TEST_GET_OBJECT_RANGE - 1)
        )
        self.assertIn('ETag', rs)
        self.assertEqual(etag, rs['ETag'])
        self.assertEqual(rs['ContentLength'], TEST_GET_OBJECT_RANGE)

        # clean up
        self._delete_bucket(TEST_BUCKET_NAME_2, [TEST_KEY_2])

    def test_get_object_versioning(self):
        bucket_name = 'bucket-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        rs = self.s3_client.list_object_versions(
            Bucket=bucket_name,
            EncodingType='url'
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['Name'], bucket_name)

        # clean up
        self._delete_bucket(bucket_name, [])

    def test_bucket_versioning(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_VERSIONING,
                                             VersioningConfiguration={'Status': 'Enabled'})

        result = self.s3_client.get_bucket_versioning(Bucket=TEST_BUCKET_WITH_VERSIONING)
        self.assertEqual(result['Status'], 'Enabled')

    def test_get_bucket_versioning_order(self):
        bucket_name = 'version-order-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_bucket_versioning(Bucket=bucket_name,
                                             VersioningConfiguration={'Status': 'Enabled'})
        self.s3_client.put_object(Bucket=bucket_name, Key='test', Body='body')
        self.s3_client.put_object(Bucket=bucket_name, Key='test', Body='body')
        self.s3_client.put_object(Bucket=bucket_name, Key='test2', Body='body')
        rs = self.s3_client.list_object_versions(
            Bucket=bucket_name,
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['Name'], bucket_name)
        self.assertEqual(rs['Versions'][0]['IsLatest'], True)
        self.assertEqual(rs['Versions'][2]['IsLatest'], True)

    def test_upload_big_file(self):
        bucket_name = 'bucket-big-file-%s' % short_uid()
        key1 = 'test_key1'
        key2 = 'test_key1'

        self.s3_client.create_bucket(Bucket=bucket_name)

        body1 = '\x01' * 10000000
        rs = self.s3_client.put_object(Bucket=bucket_name, Key=key1, Body=body1)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        body2 = 'a' * 10000000
        rs = self.s3_client.put_object(Bucket=bucket_name, Key=key2, Body=body2)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = self.s3_client.head_object(Bucket=bucket_name, Key=key1)
        self.assertEqual(rs['ContentLength'], len(body1))

        rs = self.s3_client.head_object(Bucket=bucket_name, Key=key2)
        self.assertEqual(rs['ContentLength'], len(body2))

        # clean up
        self._delete_bucket(bucket_name, [key1, key2])

    def test_s3_put_more_than_1000_items(self):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_NAME_2)
        for i in range(0, 1010, 1):
            body = 'test-' + str(i)
            key = 'test-key-' + str(i)
            self.s3_client.put_object(Bucket=TEST_BUCKET_NAME_2, Key=key, Body=body)

        # trying to get the last item of 1010 items added.
        resp = self.s3_client.get_object(Bucket=TEST_BUCKET_NAME_2, Key='test-key-1009')
        self.assertEqual(to_str(resp['Body'].read()), 'test-1009')

        # trying to get the first item of 1010 items added.
        resp = self.s3_client.get_object(Bucket=TEST_BUCKET_NAME_2, Key='test-key-0')
        self.assertEqual(to_str(resp['Body'].read()), 'test-0')

        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2, MaxKeys=1010)
        self.assertEqual(len(resp['Contents']), 1010)

        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2)
        self.assertEqual(len(resp['Contents']), 1000)
        next_marker = resp['NextMarker']

        # Second list
        resp = self.s3_client.list_objects(Bucket=TEST_BUCKET_NAME_2, Marker=next_marker)
        self.assertEqual(len(resp['Contents']), 10)

    def test_s3_list_objects_empty_marker(self):
        bucket_name = 'test' + short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        resp = self.s3_client.list_objects(Bucket=bucket_name, Marker='')
        self.assertEqual(resp['Marker'], '')

    def test_s3_multipart_upload_file(self):
        def upload(size_in_mb, bucket):
            file_name = '{}.tmp'.format(short_uid())
            path = '{}'.format(file_name)
            with open(path, 'wb') as f:
                f.seek(int(size_in_mb * 1e6))
                f.write(b'\0')
                f.flush()
                self.s3_client.upload_file(
                    path,
                    bucket,
                    f'{file_name}',
                    ExtraArgs={'StorageClass': 'DEEP_ARCHIVE'}
                )

            os.remove(path)

        bucket_name = 'bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        upload(1, bucket_name)
        upload(9, bucket_name)
        upload(15, bucket_name)

        s3_resource = aws_stack.connect_to_resource('s3')
        objects = s3_resource.Bucket(bucket_name).objects.all()
        keys = []
        for obj in objects:
            keys.append(obj.key)
            self.assertEqual(obj.storage_class, 'DEEP_ARCHIVE')

        self._delete_bucket(bucket_name, keys)

    def test_cors_with_single_origin_error(self):
        client = self._get_test_client()

        BUCKET_CORS_CONFIG = {
            'CORSRules': [{
                'AllowedOrigins': ['https://localhost:4200'],
                'AllowedMethods': ['GET', 'PUT'],
                'MaxAgeSeconds': 3000,
                'AllowedHeaders': ['*'],
            }]
        }

        client.create_bucket(Bucket='my-s3-bucket')
        client.put_bucket_cors(Bucket='my-s3-bucket', CORSConfiguration=BUCKET_CORS_CONFIG)

        # create signed url
        url = client.generate_presigned_url(
            ClientMethod='put_object',
            Params={
                'Bucket': 'my-s3-bucket',
                'Key': '424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf',
                'ContentType': 'application/pdf',
                'ACL': 'bucket-owner-full-control'
            },
            ExpiresIn=3600
        )

        result = requests.put(url, data='something', verify=False,
                              headers={'Origin': 'https://localhost:4200', 'Content-Type': 'application/pdf'})
        self.assertEqual(result.status_code, 200)

        BUCKET_CORS_CONFIG = {
            'CORSRules': [{
                'AllowedOrigins': ['https://localhost:4200', 'https://localhost:4201'],
                'AllowedMethods': ['GET', 'PUT'],
                'MaxAgeSeconds': 3000,
                'AllowedHeaders': ['*'],
            }]
        }

        client.put_bucket_cors(Bucket='my-s3-bucket', CORSConfiguration=BUCKET_CORS_CONFIG)

        # create signed url
        url = client.generate_presigned_url(
            ClientMethod='put_object',
            Params={
                'Bucket': 'my-s3-bucket',
                'Key': '424f6bae-c48f-42d8-9e25-52046aecc64d/document.pdf',
                'ContentType': 'application/pdf',
                'ACL': 'bucket-owner-full-control'
            },
            ExpiresIn=3600
        )

        result = requests.put(url, data='something', verify=False,
                              headers={'Origin': 'https://localhost:4200', 'Content-Type': 'application/pdf'})
        self.assertEqual(result.status_code, 200)

        result = requests.put(url, data='something', verify=False,
                              headers={'Origin': 'https://localhost:4201', 'Content-Type': 'application/pdf'})
        self.assertEqual(result.status_code, 200)

    def test_s3_put_object_notification_with_lambda(self):
        bucket_name = 'bucket-%s' % short_uid()
        function_name = 'func-%s' % short_uid()
        table_name = 'table-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36
        )

        aws_stack.create_dynamodb_table(
            table_name=table_name,
            partition_key='uuid'
        )

        self.s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'LambdaFunctionConfigurations': [
                    {
                        'LambdaFunctionArn': aws_stack.lambda_function_arn(function_name),
                        'Events': ['s3:ObjectCreated:*']
                    }
                ]
            }
        )

        # put an object
        obj = self.s3_client.put_object(Bucket=bucket_name, Key=table_name, Body='something..')
        etag = obj['ETag']
        time.sleep(2)

        table = aws_stack.connect_to_resource('dynamodb').Table(table_name)

        def check_table():
            rs = table.scan()
            self.assertEqual(len(rs['Items']), 1)
            return rs

        rs = retry(check_table, retries=4, sleep=3)

        record = rs['Items'][0]
        self.assertEqual(record['data']['s3']['bucket']['name'], bucket_name)
        self.assertEqual(record['data']['s3']['object']['eTag'], etag)

        # clean up
        self._delete_bucket(bucket_name, [table_name])

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.delete_function(FunctionName=function_name)

        dynamodb_client = aws_stack.connect_to_service('dynamodb')
        dynamodb_client.delete_table(TableName=table_name)

    def test_s3_put_object_notification_with_sns_topic(self):
        bucket_name = 'bucket-%s' % short_uid()
        topic_name = 'topic-%s' % short_uid()
        queue_name = 'queue-%s' % short_uid()
        key_name = 'bucket-key-%s' % short_uid()

        sns_client = aws_stack.connect_to_service('sns')

        self.s3_client.create_bucket(Bucket=bucket_name)
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']

        topic_arn = sns_client.create_topic(Name=topic_name)['TopicArn']

        sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=aws_stack.sqs_queue_arn(queue_name))

        self.s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'TopicConfigurations': [
                    {
                        'TopicArn': topic_arn,
                        'Events': ['s3:ObjectCreated:*']
                    }
                ]
            }
        )

        # Put an object
        # This will trigger an event to sns topic, sqs queue will get a message since it's a subscriber of topic
        self.s3_client.put_object(Bucket=bucket_name, Key=key_name, Body='body content...')
        time.sleep(2)

        def get_message(q_url):
            resp = self.sqs_client.receive_message(QueueUrl=q_url)
            m = resp['Messages'][0]
            self.sqs_client.delete_message(
                QueueUrl=q_url,
                ReceiptHandle=m['ReceiptHandle']
            )
            return json.loads(m['Body'])

        message = retry(get_message, retries=3, sleep=2, q_url=queue_url)
        # We got a notification message in sqs queue (from s3 source)
        self.assertEqual(message['Type'], 'Notification')
        self.assertEqual(message['TopicArn'], topic_arn)
        self.assertEqual(message['Subject'], 'Amazon S3 Notification')

        r = json.loads(message['Message'])['Records'][0]
        self.assertEqual(r['eventSource'], 'aws:s3')
        self.assertEqual(r['s3']['bucket']['name'], bucket_name)
        self.assertEqual(r['s3']['object']['key'], key_name)

        # clean up
        self._delete_bucket(bucket_name, [key_name])
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        sns_client.delete_topic(TopicArn=topic_arn)

    def test_s3_get_deep_archive_object(self):
        bucket_name = 'bucket-%s' % short_uid()
        object_key = 'key-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)

        # put DEEP_ARCHIVE object
        self.s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body='body data',
            StorageClass='DEEP_ARCHIVE'
        )

        with self.assertRaises(ClientError) as ctx:
            self.s3_client.get_object(
                Bucket=bucket_name,
                Key=object_key
            )

        self.assertIn('InvalidObjectState', str(ctx.exception))

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_get_deep_archive_object_restore(self):
        bucket_name = 'bucket-%s' % short_uid()
        object_key = 'key-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)

        # put DEEP_ARCHIVE object
        self.s3_client.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body='body data',
            StorageClass='DEEP_ARCHIVE'
        )

        with self.assertRaises(ClientError) as ctx:
            self.s3_client.get_object(
                Bucket=bucket_name,
                Key=object_key
            )

        self.assertIn('InvalidObjectState', str(ctx.exception))

        # put DEEP_ARCHIVE object
        self.s3_client.restore_object(
            Bucket=bucket_name,
            Key=object_key,
            RestoreRequest={
                'Days': 30,
                'GlacierJobParameters': {
                    'Tier': 'Bulk'
                },
                'Tier': 'Bulk',
            },
        )

        response = self.s3_client.get_object(
            Bucket=bucket_name,
            Key=object_key
        )

        self.assertIn('etag', response.get('ResponseMetadata').get('HTTPHeaders'))

        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_encoding_notification_messages(self):
        key = 'a@b'
        bucket_name = 'notif-enc-%s' % short_uid()
        queue_url = self.sqs_client.create_queue(QueueName='testQueue')['QueueUrl']
        queue_attributes = self.sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])

        self._create_test_notification_bucket(queue_attributes, bucket_name=bucket_name)

        # put an object where the bucket_name is in the path
        self.s3_client.put_object(Bucket=bucket_name, Key=key, Body='something')

        response = self.sqs_client.receive_message(QueueUrl=queue_url)
        self.assertEqual(json.loads(response['Messages'][0]['Body'])['Records'][0]['s3']['object']['key'], 'a%40b')
        # clean up
        self.s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': key}]})

    def test_s3_batch_delete_objects_using_requests(self):
        bucket_name = 'bucket-%s' % short_uid()
        object_key_1 = 'key-%s' % short_uid()
        object_key_2 = 'key-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key_1, Body='This body document')
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key_2, Body='This body document')

        base_url = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_S3)
        url = '{}/{}?delete='.format(base_url, bucket_name)
        r = requests.post(url=url, data=BATCH_DELETE_BODY % (object_key_1, object_key_2))

        self.assertEqual(r.status_code, 200)

        s3_resource = aws_stack.connect_to_resource('s3')
        bucket = s3_resource.Bucket(bucket_name)

        total_keys = sum(1 for _ in bucket.objects.all())
        self.assertEqual(total_keys, 0)

        # clean up
        self._delete_bucket(bucket_name, [])

    def test_presigned_url_signature_authentication(self):
        client = boto3.client('s3', endpoint_url=config.get_edge_url(),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY)
        client_v4 = boto3.client('s3', endpoint_url=config.get_edge_url(),
            config=Config(signature_version='s3v4'), aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY)

        OBJECT_KEY = 'temp.txt'
        OBJECT_DATA = 'this should be found in when you download {}.'.format(OBJECT_KEY)
        BUCKET = 'test'
        EXPIRES = 4

        def make_v2_url_invalid(url):
            parsed = urlparse.urlparse(url)
            query_params = parse_qs(parsed.query)
            url = '{}/{}/{}?AWSAccessKeyId={}&Signature={}&Expires={}'.format(
                config.get_edge_url(), BUCKET, OBJECT_KEY,
                'test', query_params['Signature'][0], query_params['Expires'][0]
            )
            return url

        def make_v4_url_invalid(url):
            parsed = urlparse.urlparse(url)
            query_params = parse_qs(parsed.query)
            url = ('{}/{}/{}?X-Amz-Algorithm=AWS4-HMAC-SHA256&' +
                   'X-Amz-Credential={}&X-Amz-Date={}&' +
                   'X-Amz-Expires={}&X-Amz-SignedHeaders=host&' +
                   'X-Amz-Signature={}').format(
                config.get_edge_url(), BUCKET, OBJECT_KEY,
                quote(query_params['X-Amz-Credential'][0]).replace('/', '%2F'),
                query_params['X-Amz-Date'][0], query_params['X-Amz-Expires'][0], query_params['X-Amz-Signature'][0]
            )
            return url

        client.create_bucket(Bucket=BUCKET)

        client.put_object(
            Key=OBJECT_KEY,
            Bucket=BUCKET,
            Body='123'
        )

        presign_get_url = client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.get(presign_get_url)
        self.assertEqual(response.status_code, 200)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 200)

        presign_get_url = client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ResponseContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ResponseContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.get(presign_get_url)
        self.assertEqual(response.status_code, 200)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 200)

        # Invalid request
        url = make_v2_url_invalid(presign_get_url)
        response = requests.get(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_get_url_v4)
        response = requests.get(url, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        # PUT Requests
        presign_put_url = client.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.put(presign_put_url, data=OBJECT_DATA)
        self.assertEqual(response.status_code, 200)

        response = requests.put(presign_put_url_v4, data=OBJECT_DATA)
        self.assertEqual(response.status_code, 200)

        presign_put_url = client.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.put(presign_put_url, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 200)

        response = requests.put(presign_put_url_v4, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 200)

        # Invalid request
        url = make_v2_url_invalid(presign_put_url)
        response = requests.put(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_put_url_v4)
        response = requests.put(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        # DELETE Requests
        presign_delete_url = client.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request

        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 204)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 204)

        presign_delete_url = client.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'VersionId': '1'},
            ExpiresIn=EXPIRES
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'VersionId': '1'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 204)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 204)

        # Invalid request
        url = make_v2_url_invalid(presign_delete_url)
        response = requests.delete(url)
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_delete_url_v4)
        response = requests.delete(url)
        self.assertEqual(response.status_code, 403)

        # Expired requests
        time.sleep(4)

        # GET
        response = requests.get(presign_get_url)
        self.assertEqual(response.status_code, 403)
        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 403)

        # PUT
        response = requests.put(presign_put_url, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 403)
        response = requests.put(presign_put_url_v4, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 403)

        # DELETE
        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 403)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 403)

        client.delete_object(Bucket=BUCKET, Key=OBJECT_KEY)
        client.delete_bucket(Bucket=BUCKET)

    def test_presigned_url_signature_authentication_virtual_host_addressing(self):
        return  # TODO: test temporarily disabled!
        virtual_endpoint = '{}://{}:{}'.format(
            config.get_protocol(), S3_VIRTUAL_HOSTNAME, config.EDGE_PORT)
        client = boto3.client('s3', endpoint_url=virtual_endpoint,
            config=Config(s3={'addressing_style': 'virtual'}),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY)
        client_v4 = boto3.client('s3', endpoint_url=virtual_endpoint,
            config=Config(signature_version='s3v4', s3={'addressing_style': 'virtual'}),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY)

        OBJECT_KEY = 'temp.txt'
        OBJECT_DATA = 'this should be found in when you download {}.'.format(OBJECT_KEY)
        BUCKET = 'test'
        EXPIRES = 4

        def make_v2_url_invalid(url):
            parsed = urlparse.urlparse(url)
            query_params = parse_qs(parsed.query)
            url = '{}/{}?AWSAccessKeyId={}&Signature={}&Expires={}'.format(
                virtual_endpoint, OBJECT_KEY,
                'test', query_params['Signature'][0], query_params['Expires'][0]
            )
            return url

        def make_v4_url_invalid(url):
            parsed = urlparse.urlparse(url)
            query_params = parse_qs(parsed.query)
            url = ('{}/{}?X-Amz-Algorithm=AWS4-HMAC-SHA256&' +
                   'X-Amz-Credential={}&X-Amz-Date={}&' +
                   'X-Amz-Expires={}&X-Amz-SignedHeaders=host&' +
                   'X-Amz-Signature={}').format(
                virtual_endpoint, OBJECT_KEY,
                quote(query_params['X-Amz-Credential'][0]).replace('/', '%2F'),
                query_params['X-Amz-Date'][0], query_params['X-Amz-Expires'][0], query_params['X-Amz-Signature'][0]
            )
            return url

        self.s3_client.create_bucket(Bucket=BUCKET)

        self.s3_client.put_object(
            Key=OBJECT_KEY,
            Bucket=BUCKET,
            Body='123'
        )

        # GET requests
        presign_get_url = client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.get(presign_get_url)
        self.assertEqual(response.status_code, 200)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 200)

        presign_get_url_get = client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ResponseContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        presign_get_url_v4 = client_v4.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ResponseContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.get(presign_get_url_get)
        self.assertEqual(response.status_code, 200)

        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 200)

        # Invalid request
        url = make_v2_url_invalid(presign_get_url)
        response = requests.get(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_get_url_v4)
        response = requests.get(url, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        # PUT Requests
        presign_put_url = client.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.put(presign_put_url, data=OBJECT_DATA)
        self.assertEqual(response.status_code, 200)

        response = requests.put(presign_put_url_v4, data=OBJECT_DATA)
        self.assertEqual(response.status_code, 200)

        presign_put_url = client.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        presign_put_url_v4 = client_v4.generate_presigned_url(
            'put_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'ContentType': 'text/plain'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.put(presign_put_url, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 200)

        response = requests.put(presign_put_url_v4, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 200)

        # Invalid request
        url = make_v2_url_invalid(presign_put_url)
        response = requests.put(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_put_url_v4)
        response = requests.put(url, data=OBJECT_DATA, headers={'Content-Type': 'my-fake-content/type'})
        self.assertEqual(response.status_code, 403)

        # DELETE Requests
        presign_delete_url = client.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY},
            ExpiresIn=EXPIRES
        )

        # Valid request

        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 204)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 204)

        presign_delete_url = client.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'VersionId': '1'},
            ExpiresIn=EXPIRES
        )

        presign_delete_url_v4 = client_v4.generate_presigned_url(
            'delete_object',
            Params={'Bucket': BUCKET, 'Key': OBJECT_KEY, 'VersionId': '1'},
            ExpiresIn=EXPIRES
        )

        # Valid request
        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 204)

        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 204)

        # Invalid request
        url = make_v2_url_invalid(presign_delete_url)
        response = requests.delete(url)
        self.assertEqual(response.status_code, 403)

        url = make_v4_url_invalid(presign_delete_url_v4)
        response = requests.delete(url)
        self.assertEqual(response.status_code, 403)

        # Expired requests
        time.sleep(4)

        # GET
        response = requests.get(presign_get_url)
        self.assertEqual(response.status_code, 403)
        response = requests.get(presign_get_url_v4)
        self.assertEqual(response.status_code, 403)

        # PUT
        response = requests.put(presign_put_url, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 403)
        response = requests.put(presign_put_url_v4, data=OBJECT_DATA, headers={'Content-Type': 'text/plain'})
        self.assertEqual(response.status_code, 403)

        # DELETE
        response = requests.delete(presign_delete_url)
        self.assertEqual(response.status_code, 403)
        response = requests.delete(presign_delete_url_v4)
        self.assertEqual(response.status_code, 403)

        client.delete_object(Bucket=BUCKET, Key=OBJECT_KEY)
        client.delete_bucket(Bucket=BUCKET)

    def test_precondition_failed_error(self):
        bucket = 'bucket-%s' % short_uid()
        client = self._get_test_client()

        client.create_bucket(Bucket=bucket)
        client.put_object(Bucket=bucket, Key='foo', Body=b'{"foo": "bar"}')

        # this line makes localstack crash:
        try:
            client.get_object(Bucket=bucket, Key='foo', IfMatch='"not good etag"')
        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'PreconditionFailed')
            self.assertEqual(e.response['Error']['Message'], 'At least one of the pre-conditions you '
                                                             'specified did not hold')

        client.delete_object(Bucket=bucket, Key='foo')
        client.delete_bucket(Bucket=bucket)

    def test_cors_configurtaions(self):
        client = self._get_test_client()
        bucket = 'test-cors'
        object_key = 'index.html'
        url = '{}/{}/{}'.format(config.get_edge_url(), bucket, object_key)

        BUCKET_CORS_CONFIG = {
            'CORSRules': [{
                'AllowedOrigins': [config.get_edge_url()],
                'AllowedMethods': ['GET', 'PUT'],
                'MaxAgeSeconds': 3000,
                'AllowedHeaders': ['x-amz-tagging'],
            }]
        }

        client.create_bucket(Bucket=bucket)
        client.put_bucket_cors(Bucket=bucket, CORSConfiguration=BUCKET_CORS_CONFIG)

        client.put_object(Bucket=bucket, Key=object_key, Body='<h1>Index</html>')

        response = requests.get(url,
                              headers={'Origin': config.get_edge_url(), 'Content-Type': 'text/html'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Access-Control-Allow-Origin'.lower(), response.headers)
        self.assertEqual(response.headers['Access-Control-Allow-Origin'], config.get_edge_url())
        self.assertIn('Access-Control-Allow-Methods'.lower(), response.headers)
        self.assertIn('GET', response.headers['Access-Control-Allow-Methods'])
        self.assertIn('Access-Control-Allow-Headers', response.headers)
        self.assertEqual(response.headers['Access-Control-Allow-Headers'], 'x-amz-tagging')
        self.assertIn('Access-Control-Max-Age'.lower(), response.headers)
        self.assertEqual(response.headers['Access-Control-Max-Age'], '3000')
        self.assertIn('Access-Control-Allow-Credentials'.lower(), response.headers)
        self.assertEqual(response.headers['Access-Control-Allow-Credentials'].lower(), 'true')

        BUCKET_CORS_CONFIG = {
            'CORSRules': [{
                'AllowedOrigins': ['https://anydomain.com'],
                'AllowedMethods': ['GET', 'PUT'],
                'MaxAgeSeconds': 3000,
                'AllowedHeaders': ['x-amz-tagging'],
            }]
        }

        client.put_bucket_cors(Bucket=bucket, CORSConfiguration=BUCKET_CORS_CONFIG)
        response = requests.get(url,
                              headers={'Origin': config.get_edge_url(), 'Content-Type': 'text/html'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Access-Control-Allow-Origin'.lower(), response.headers)
        self.assertNotIn('Access-Control-Allow-Methods'.lower(), response.headers)
        self.assertNotIn('Access-Control-Allow-Headers', response.headers)
        self.assertNotIn('Access-Control-MaxAge', response.headers)

        # cleaning
        client.delete_object(Bucket=bucket, Key=object_key)
        client.delete_bucket(Bucket=bucket)

    def test_s3_download_object_with_lambda(self):
        bucket_name = 'bucket-%s' % short_uid()
        function_name = 'func-%s' % short_uid()
        key = 'key-%s' % short_uid()

        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key=key, Body='something..')

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_DOWNLOAD_FROM_S3,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            envvars=dict({
                'BUCKET_NAME': bucket_name,
                'OBJECT_NAME': key,
                'LOCAL_FILE_NAME': '/tmp/' + key,
            })
        )

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.invoke(FunctionName=function_name, InvocationType='Event')

        retry(testutil.check_expected_lambda_log_events_length, retries=10,
              sleep=3, function_name=function_name, expected_length=1)

        # clean up
        self._delete_bucket(bucket_name, [key])
        lambda_client.delete_function(FunctionName=function_name)

    def test_putobject_with_multiple_keys(self):
        client = self._get_test_client()
        bucket = 'bucket-%s' % short_uid()
        key_by_path = 'aws/key1/key2/key3'

        client.create_bucket(Bucket=bucket)
        client.put_object(
            Body=b'test',
            Bucket=bucket,
            Key=key_by_path
        )

        # Cleanup
        self._delete_bucket(bucket, key_by_path)

    def test_terraform_request_sequence(self):

        reqs = load_file(os.path.join(os.path.dirname(__file__), 'files', 's3.requests.txt'))
        reqs = reqs.split('---')

        for req in reqs:
            header, _, body = req.strip().partition('\n\n')
            req, _, headers = header.strip().partition('\n')
            headers = {h.split(':')[0]: h.partition(':')[2].strip() for h in headers.split('\n')}
            method, path, _ = req.split(' ')
            url = '%s%s' % (config.get_edge_url(), path)
            result = getattr(requests, method.lower())(url, data=body, headers=headers)
            self.assertLess(result.status_code, 400)

    # ---------------
    # HELPER METHODS
    # ---------------

    @staticmethod
    def generate_large_file(size):
        # https://stackoverflow.com/questions/8816059/create-file-of-particular-size-in-python
        filename = 'large_file_%s' % uuid.uuid4()
        f = open(filename, 'wb')
        f.seek(size - 1)
        f.write(b'\0')
        f.close()
        return open(filename, 'r')

    def _create_test_queue(self):
        queue_url = self.sqs_client.create_queue(QueueName=TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION)['QueueUrl']
        queue_attributes = self.sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])
        return queue_url, queue_attributes

    def _create_test_notification_bucket(self, queue_attributes, bucket_name):
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'QueueConfigurations': [
                    {
                        'QueueArn': queue_attributes['Attributes']['QueueArn'],
                        'Events': ['s3:ObjectCreated:*']
                    }
                ]
            }
        )

    def _get_test_queue_message_count(self, queue_url):
        queue_attributes = self.sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessages']
        )
        return queue_attributes['Attributes']['ApproximateNumberOfMessages']

    def _delete_bucket(self, bucket_name, keys=[]):
        keys = keys if isinstance(keys, list) else [keys]
        objects = [{'Key': k} for k in keys]
        if objects:
            self.s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects})
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def _perform_multipart_upload(self, bucket, key, data=None, zip=False, acl=None):
        kwargs = {'ACL': acl} if acl else {}
        multipart_upload_dict = self.s3_client.create_multipart_upload(Bucket=bucket, Key=key, **kwargs)
        upload_id = multipart_upload_dict['UploadId']

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zip:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode='w') as filestream:
                filestream.write(data)

        response = self.s3_client.upload_part(Bucket=bucket, Key=key,
            Body=upload_file_object, PartNumber=1, UploadId=upload_id)

        multipart_upload_parts = [{'ETag': response['ETag'], 'PartNumber': 1}]

        return self.s3_client.complete_multipart_upload(
            Bucket=bucket, Key=key, MultipartUpload={'Parts': multipart_upload_parts}, UploadId=upload_id
        )

    def _perform_presigned_url_upload(self, bucket, key):
        client = self._get_test_client()
        url = client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket, 'Key': key}
        )
        url = url + '&X-Amz-Credential=x&X-Amz-Signature=y'
        requests.put(url, data='something', verify=False)

    def _get_test_client(self):
        return boto3.client(
            's3',
            endpoint_url=config.get_edge_url(),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY
        )
