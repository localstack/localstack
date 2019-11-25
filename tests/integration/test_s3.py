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

TEST_BUCKET_NAME_WITH_POLICY = 'test_bucket_policy_1'
TEST_BUCKET_WITH_NOTIFICATION = 'test_bucket_notification_1'
TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION = 'test_queue_for_bucket_notification_1'


class PutRequest(Request):
    """ Class to handle putting with urllib """

    def __init__(self, *args, **kwargs):
        return Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        return 'PUT'


class S3ListenerTest (unittest.TestCase):

    def setUp(self):
        self.s3_client = aws_stack.connect_to_service('s3')
        self.sqs_client = aws_stack.connect_to_service('sqs')

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
        url = '{}/{}'.format(os.getenv('TEST_S3_URL'), key_by_host)
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

    def test_s3_get_response_content_type_same_as_upload(self):
        bucket_name = 'test-bucket-%s' % short_uid()
        self.s3_client.create_bucket(Bucket=bucket_name)

        # put object
        object_key = 'key-by-hostname'
        self.s3_client.put_object(Bucket=bucket_name,
                                  Key=object_key,
                                  Body='something',
                                  ContentType='text/html; charset=utf-8')
        url = self.s3_client.generate_presigned_url(
            'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
        )

        # get object and assert headers
        response = requests.get(url, verify=False)
        self.assertEqual(response.headers['content-type'], 'text/html; charset=utf-8')
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
        url = '%s/%s/%s' % (os.environ['TEST_S3_URL'], bucket_name, object_key)
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

    def test_bucket_exists(self):
        # Test setup
        bucket = 'test-bucket'

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
            QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessages'])
        return queue_attributes['Attributes']['ApproximateNumberOfMessages']

    def _delete_bucket(self, bucket_name, keys):
        keys = keys if isinstance(keys, list) else [keys]
        objects = [{'Key': k} for k in keys]
        self.s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects})
        self.s3_client.delete_bucket(Bucket=bucket_name)

    def _perform_multipart_upload(self, bucket, key, data=None, zip=False, acl=None):
        acl = acl or 'private'
        multipart_upload_dict = self.s3_client.create_multipart_upload(Bucket=bucket, Key=key, ACL=acl)
        uploadId = multipart_upload_dict['UploadId']

        # Write contents to memory rather than a file.
        data = data or (5 * short_uid())
        data = to_bytes(data)
        upload_file_object = BytesIO(data)
        if zip:
            upload_file_object = BytesIO()
            with gzip.GzipFile(fileobj=upload_file_object, mode='w') as filestream:
                filestream.write(data)

        response = self.s3_client.upload_part(Bucket=bucket, Key=key,
            Body=upload_file_object, PartNumber=1, UploadId=uploadId)

        multipart_upload_parts = [{'ETag': response['ETag'], 'PartNumber': 1}]

        return self.s3_client.complete_multipart_upload(Bucket=bucket,
            Key=key, MultipartUpload={'Parts': multipart_upload_parts}, UploadId=uploadId)

    def _perform_presigned_url_upload(self, bucket, key):
        url = self.s3_client.generate_presigned_url(
            'put_object', Params={'Bucket': bucket, 'Key': key}
        )
        url = url + '&X-Amz-Credential=x&X-Amz-Signature=y'
        requests.put(url, data='something', verify=False)
