import io
import os
import ssl
import gzip
import json
import uuid
import unittest
import requests
from io import BytesIO
from six.moves.urllib.request import Request, urlopen
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    short_uid, get_service_protocol, to_bytes, safe_requests, to_str, new_tmp_file, rm_rf)

TEST_BUCKET_NAME_WITH_POLICY = 'test-bucket-policy-1'
TEST_BUCKET_WITH_NOTIFICATION = 'test-bucket-notification-1'
TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION = 'test_queue_for_bucket_notification_1'
TEST_BUCKET_WITH_VERSIONING = 'test-bucket-versioning-1'

TEST_BUCKET_NAME_2 = 'test-bucket-2'
TEST_KEY_2 = 'test-key-2'
TEST_GET_OBJECT_RANGE = 17


class PutRequest(Request):
    """ Class to handle putting with urllib """
    def __init__(self, *args, **kwargs):
        return Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return 'PUT'


class S3ListenerTest(unittest.TestCase):
    def setUp(self):
        self.s3_client = aws_stack.connect_to_service('s3')
        self.sqs_client = aws_stack.connect_to_service('sqs')

    def test_create_bucket_via_host_name(self):
        body = """<?xml version="1.0" encoding="UTF-8"?>
            <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <LocationConstraint>eu-central-1</LocationConstraint>
            </CreateBucketConfiguration>"""
        headers = aws_stack.mock_aws_request_headers('s3')
        bucket_name = 'test-%s' % short_uid()
        headers['Host'] = '%s.s3.amazonaws.com' % bucket_name
        response = requests.put(config.TEST_S3_URL, data=body, headers=headers, verify=False)
        self.assertEquals(response.status_code, 200)
        response = self.s3_client.get_bucket_location(Bucket=bucket_name)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('LocationConstraint', response)

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
        key_by_path = 'key-by-hostname'
        key_by_host = 'key-by-host'
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes)
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                             VersioningConfiguration={'Status': 'Enabled'})

        # put an object where the bucket_name is in the path
        obj = self.s3_client.put_object(Bucket=TEST_BUCKET_WITH_NOTIFICATION, Key=key_by_path, Body='something')

        # put an object where the bucket_name is in the host
        # it doesn't care about the authorization header as long as it's present
        headers = {'Host': '{}.s3.amazonaws.com'.format(TEST_BUCKET_WITH_NOTIFICATION), 'authorization': 'some_token'}
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
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                             VersioningConfiguration={'Status': 'Disabled'})
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(TEST_BUCKET_WITH_NOTIFICATION, [key_by_path, key_by_host])

    def generate_large_file(self, size):
        # https://stackoverflow.com/questions/8816059/create-file-of-particular-size-in-python
        filename = 'large_file_%s' % uuid.uuid4()
        f = open(filename, 'wb')
        f.seek(size - 1)
        f.write(b'\0')
        f.close()
        return open(filename, 'r')

    def test_s3_upload_fileobj_with_large_file_notification(self):
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes)

        # has to be larger than 64MB to be broken up into a multipart upload
        file_size = 75000000
        large_file = self.generate_large_file(file_size)
        download_file = new_tmp_file()
        try:
            self.s3_client.upload_file(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                       Key=large_file.name, Filename=large_file.name)

            self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

            # ensure that the first message's eventName is ObjectCreated:CompleteMultipartUpload
            messages = self.sqs_client.receive_message(QueueUrl=queue_url, AttributeNames=['All'])
            message = json.loads(messages['Messages'][0]['Body'])
            self.assertEqual(message['Records'][0]['eventName'], 'ObjectCreated:CompleteMultipartUpload')

            # download the file, check file size
            self.s3_client.download_file(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                         Key=large_file.name, Filename=download_file)
            self.assertEqual(os.path.getsize(download_file), file_size)

            # clean up
            self.sqs_client.delete_queue(QueueUrl=queue_url)
            self._delete_bucket(TEST_BUCKET_WITH_NOTIFICATION, large_file.name)
        finally:
            # clean up large files
            large_file.close()
            rm_rf(large_file.name)
            rm_rf(download_file)

    def test_s3_multipart_upload_with_small_single_part(self):
        # In a multipart upload "Each part must be at least 5 MB in size, except the last part."
        # https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadComplete.html

        key_by_path = 'key-by-hostname'
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes)

        # perform upload
        self._perform_multipart_upload(bucket=TEST_BUCKET_WITH_NOTIFICATION, key=key_by_path, zip=True)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(TEST_BUCKET_WITH_NOTIFICATION, [key_by_path])

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
        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes)

        self._perform_presigned_url_upload(bucket=TEST_BUCKET_WITH_NOTIFICATION, key=key_by_path)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(TEST_BUCKET_WITH_NOTIFICATION, [key_by_path])

    def test_s3_get_response_default_content_type(self):
        # When no content type is provided by a PUT request
        # 'binary/octet-stream' should be used
        # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html

        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        url = self.s3_client.generate_presigned_url(
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
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        url = self.s3_client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket_name, 'Key': object_key})
        # append metadata manually to URL (this is not easily possible with boto3, as "Metadata" cannot
        # be passed to generate_presigned_url, and generate_presigned_post works differently)
        url += '&x-amz-meta-foo=bar'

        # get object and assert metadata is present
        response = requests.put(url, data='content 123', verify=False)
        self.assertLess(response.status_code, 400)
        # response body should be empty, see https://github.com/localstack/localstack/issues/1317
        self.assertEqual('', to_str(response.content))
        response = self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
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
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = '/foo/bar/key-by-hostname'
        content_type = 'foo/bar; charset=utf-8'
        self.s3_client.put_object(Bucket=bucket_name,
                                  Key=object_key,
                                  Body='something ' * 20,
                                  ContentType=content_type)
        url = self.s3_client.generate_presigned_url(
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

    def test_s3_head_response_content_length_same_as_upload(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        body = 'something body \n \n\r'
        # put object
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=body, ContentType='text/html; charset=utf-8')
        url = self.s3_client.generate_presigned_url(
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
            Authorization: foobar
            Content-Type: audio/mpeg
            X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
            X-Amz-Date: 20190918T051509Z
            X-Amz-Decoded-Content-Length: %s
        """ % len(body)
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
        self.s3_client.create_bucket(Bucket=bucket_name)
        body = 'something body'
        # get presigned URL
        object_key = 'test-presigned-key'
        url = self.s3_client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )
        # put object
        response = requests.put(url, data=body, verify=False)
        self.assertEqual(response.status_code, 200)
        # get object and compare results
        downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        download_object = downloaded_object['Body'].read()
        self.assertEqual(to_str(body), to_str(download_object))
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_post_object_on_presigned_post(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        body = 'something body'
        # get presigned URL
        object_key = 'test-presigned-post-key'
        presigned_request = self.s3_client.generate_presigned_post(
            Bucket=bucket_name,
            Key=object_key
        )
        # put object
        files = {'file': body}
        response = requests.post(presigned_request['url'], data=presigned_request['fields'], files=files, verify=False)
        self.assertEqual(response.status_code, 200)
        # get object and compare results
        downloaded_object = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        download_object = downloaded_object['Body'].read()
        self.assertEqual(to_str(body), to_str(download_object))
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_delete_response_content_length_zero(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name,
                                  Key=object_key,
                                  Body='something',
                                  ContentType='text/html; charset=utf-8')
        url = self.s3_client.generate_presigned_url(
            'delete_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )

        # get object and assert headers
        response = requests.delete(url, verify=False)

        self.assertEqual(response.headers['content-length'], '0')
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

    def test_s3_uppercase_names(self):
        # bucket name should be case-insensitive
        bucket_name = 'TestUpperCase-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # key name should be case-sensitive
        object_key = 'camelCaseKey'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        self.assertRaises(Exception, self.s3_client.get_object, Bucket=bucket_name, Key=object_key.lower())

    def test_s3_get_response_headers(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object and CORS configuration
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
        self.s3_client.put_bucket_cors(Bucket=bucket_name,
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
        url = self.s3_client.generate_presigned_url(
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
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')

        # get object and assert headers
        url = self.s3_client.generate_presigned_url(
            'get_object', Params={
                'Bucket': bucket_name,
                'Key': object_key,
                'ResponseCacheControl': 'max-age=74',
                'ResponseContentDisposition': 'attachment; filename="foo.jpg"',
                'ResponseContentEncoding': 'identity',
                'ResponseContentLanguage': 'de-DE',
                'ResponseContentType': 'image/jpeg',
                'ResponseExpires': 'Wed, 21 Oct 2015 07:28:00 GMT'}
        )
        response = requests.get(url, verify=False)

        self.assertEqual(response.headers['cache-control'], 'max-age=74')
        self.assertEqual(response.headers['content-disposition'], 'attachment; filename="foo.jpg"')
        self.assertEqual(response.headers['content-encoding'], 'identity')
        self.assertEqual(response.headers['content-language'], 'de-DE')
        self.assertEqual(response.headers['content-type'], 'image/jpeg')
        self.assertEqual(response.headers['expires'], '2015-10-21T07:28:00Z')
        # clean up
        self._delete_bucket(bucket_name, [object_key])

    def test_s3_copy_md5(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        src_key = 'src'
        self.s3_client.put_object(Bucket=bucket_name, Key=src_key, Body='something')

        # copy object
        dest_key = 'dest'
        response = self.s3_client.copy_object(Bucket=bucket_name, CopySource={'Bucket': bucket_name, 'Key': src_key},
                                              Key=dest_key)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # Create copy object to try to match s3a setting Content-MD5
        dest_key2 = 'dest'
        url = self.s3_client.generate_presigned_url(
            'copy_object', Params={'Bucket': bucket_name, 'CopySource': {'Bucket': bucket_name, 'Key': src_key},
                                   'Key': dest_key2}
        )
        # Set a Content-MD5 header that should be ignored on a copy request
        request_response = requests.put(url, verify=False, headers={'Content-MD5': 'ignored_md5'})
        self.assertEqual(request_response.status_code, 200)

        # Cleanup
        self._delete_bucket(bucket_name, [src_key, dest_key, dest_key2])

    def test_s3_invalid_content_md5(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object with invalid content MD5
        for hash in ['__invalid__', '000']:
            raised = False
            try:
                self.s3_client.put_object(Bucket=bucket_name, Key='test-key',
                    Body='something', ContentMD5=hash)
            except Exception:
                raised = True
            if not raised:
                raise Exception('Invalid MD5 hash "%s" should have raised an error' % hash)

        # Cleanup
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_s3_upload_download_gzip(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        data = '000000000000000000000000000000'

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

        self.assertEqual(downloaded_data, data, '{} != {}'.format(downloaded_data, data))

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

    def test_s3_website_errordocument(self):
        # check that the error document is returned when configured
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_object(Bucket=bucket_name, Key='error.html', Body='This is the error document')
        self.s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={'ErrorDocument': {'Key': 'error.html'}}
        )
        url = self.s3_client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': 'nonexistent'}
        )
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, 'This is the error document')
        # cleanup
        self.s3_client.delete_object(Bucket=bucket_name, Key='error.html')
        self.s3_client.delete_bucket(Bucket=bucket_name)

        # check that normal responses are returned for bucket with index configuration, but not error document
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        self.s3_client.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={'IndexDocument': {'Suffix': 'index.html'}}
        )
        url = self.s3_client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': 'nonexistent'}
        )
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 404)
        # cleanup
        self.s3_client.delete_bucket(Bucket=bucket_name)

        # check that normal responses are returned for bucket without configuration
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)
        url = self.s3_client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': 'nonexistent'}
        )
        response = requests.get(url, verify=False)
        self.assertEqual(response.status_code, 404)
        # cleanup
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def test_s3_event_notification_with_sqs(self):
        key_by_path = 'aws/bucket=2020/test1.txt'

        queue_url, queue_attributes = self._create_test_queue()
        self._create_test_notification_bucket(queue_attributes)
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                             VersioningConfiguration={'Status': 'Enabled'})

        body = 'Lorem ipsum dolor sit amet, ... ' * 30

        # put an object
        self.s3_client.put_object(Bucket=TEST_BUCKET_WITH_NOTIFICATION, Key=key_by_path, Body=body)

        self.assertEqual(self._get_test_queue_message_count(queue_url), '1')

        rs = self.sqs_client.receive_message(QueueUrl=queue_url)
        record = [json.loads(to_str(m['Body'])) for m in rs['Messages']][0]['Records'][0]

        download_file = new_tmp_file()
        self.s3_client.download_file(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                     Key=key_by_path, Filename=download_file)

        self.assertEqual(record['s3']['object']['size'], os.path.getsize(download_file))

        # clean up
        self.s3_client.put_bucket_versioning(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                             VersioningConfiguration={'Status': 'Disabled'})

        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self._delete_bucket(TEST_BUCKET_WITH_NOTIFICATION, [key_by_path])

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

    # ---------------
    # HELPER METHODS
    # ---------------

    def _create_test_queue(self):
        queue_url = self.sqs_client.create_queue(QueueName=TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION)['QueueUrl']
        queue_attributes = self.sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])
        return queue_url, queue_attributes

    def _create_test_notification_bucket(self, queue_attributes):
        self.s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_NOTIFICATION)
        self.s3_client.put_bucket_notification_configuration(
            Bucket=TEST_BUCKET_WITH_NOTIFICATION,
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
        url = self.s3_client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket, 'Key': key}
        )
        url = url + '&X-Amz-Credential=x&X-Amz-Signature=y'
        requests.put(url, data='something', verify=False)
