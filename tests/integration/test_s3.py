import gzip
import os
import json
import requests
from io import BytesIO
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

TEST_BUCKET_NAME_WITH_POLICY = 'test_bucket_policy_1'
TEST_BUCKET_WITH_NOTIFICATION = 'test_bucket_notification_1'
TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION = 'test_queue_for_bucket_notification_1'


def test_bucket_policy():

    s3_resource = aws_stack.connect_to_resource('s3')
    s3_client = aws_stack.connect_to_service('s3')

    # create test bucket
    s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_POLICY)

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
    response = s3_client.put_bucket_policy(
        Bucket=TEST_BUCKET_NAME_WITH_POLICY,
        Policy=json.dumps(policy)
    )
    assert response['ResponseMetadata']['HTTPStatusCode'] == 204

    # retrieve and check policy config
    saved_policy = s3_client.get_bucket_policy(Bucket=TEST_BUCKET_NAME_WITH_POLICY)['Policy']
    assert json.loads(saved_policy) == policy


def test_s3_put_object_notification():

    s3_client = aws_stack.connect_to_service('s3')
    sqs_client = aws_stack.connect_to_service('sqs')

    key_by_path = 'key-by-hostname'
    key_by_host = 'key-by-host'

    # create test queue
    queue_url = sqs_client.create_queue(QueueName=TEST_QUEUE_FOR_BUCKET_WITH_NOTIFICATION)['QueueUrl']
    queue_attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])

    # create test bucket
    s3_client.create_bucket(Bucket=TEST_BUCKET_WITH_NOTIFICATION)
    s3_client.put_bucket_notification_configuration(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                                                    NotificationConfiguration={'QueueConfigurations': [
                                                        {'QueueArn': queue_attributes['Attributes']['QueueArn'],
                                                         'Events': ['s3:ObjectCreated:*']}]})

    # put an object where the bucket_name is in the path
    s3_client.put_object(Bucket=TEST_BUCKET_WITH_NOTIFICATION, Key=key_by_path, Body='something')

    # put an object where the bucket_name is in the host
    # it doesn't care about the authorization header as long as it's present
    headers = {'Host': '{}.s3.amazonaws.com'.format(TEST_BUCKET_WITH_NOTIFICATION), 'authorization': 'some_token'}
    url = '{}/{}'.format(os.getenv('TEST_S3_URL'), key_by_host)
    # verify=False must be set as this test fails on travis because of an SSL error non-existent locally
    response = requests.put(url, data='something else', headers=headers, verify=False)
    assert response.ok

    queue_attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url,
                                                       AttributeNames=['ApproximateNumberOfMessages'])
    message_count = queue_attributes['Attributes']['ApproximateNumberOfMessages']
    # the ApproximateNumberOfMessages attribute is a string
    assert message_count == '2'

    # clean up
    sqs_client.delete_queue(QueueUrl=queue_url)
    s3_client.delete_objects(Bucket=TEST_BUCKET_WITH_NOTIFICATION,
                             Delete={'Objects': [{'Key': key_by_path}, {'Key': key_by_host}]})
    s3_client.delete_bucket(Bucket=TEST_BUCKET_WITH_NOTIFICATION)


def test_s3_get_response_default_content_type():
    # When no content type is provided by a PUT request
    # 'binary/octet-stream' should be used
    # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    # put object
    object_key = 'key-by-hostname'
    s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
    url = s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )

    # get object and assert headers
    response = requests.get(url, verify=False)
    assert response.headers['content-type'] == 'binary/octet-stream'
    # clean up
    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': object_key}]})
    s3_client.delete_bucket(Bucket=bucket_name)


def test_s3_get_response_content_type_same_as_upload():
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    # put object
    object_key = 'key-by-hostname'
    s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something', ContentType='text/html; charset=utf-8')
    url = s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )

    # get object and assert headers
    response = requests.get(url, verify=False)
    assert response.headers['content-type'] == 'text/html; charset=utf-8'
    # clean up
    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': object_key}]})
    s3_client.delete_bucket(Bucket=bucket_name)


def test_s3_head_response_content_length_same_as_upload():
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)
    body = 'something body'
    # put object
    object_key = 'key-by-hostname'
    s3_client.put_object(Bucket=bucket_name, Key=object_key, Body=body, ContentType='text/html; charset=utf-8')
    url = s3_client.generate_presigned_url(
        'head_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )

    # get object and assert headers
    response = requests.head(url, verify=False)

    assert response.headers['content-length'] == str(len(body))
    # clean up
    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': object_key}]})
    s3_client.delete_bucket(Bucket=bucket_name)


def test_s3_delete_response_content_length_zero():
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    # put object
    object_key = 'key-by-hostname'
    s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something', ContentType='text/html; charset=utf-8')
    url = s3_client.generate_presigned_url(
        'delete_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )

    # get object and assert headers
    response = requests.delete(url, verify=False)

    assert response.headers['content-length'] == '0'
    # clean up
    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': object_key}]})
    s3_client.delete_bucket(Bucket=bucket_name)


def test_s3_get_response_headers():
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    # put object and CORS configuration
    object_key = 'key-by-hostname'
    s3_client.put_object(Bucket=bucket_name, Key=object_key, Body='something')
    url = s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )
    s3_client.put_bucket_cors(Bucket=bucket_name,
        CORSConfiguration={
            'CORSRules': [{
                'AllowedMethods': ['GET', 'PUT', 'POST'],
                'AllowedOrigins': ['*'],
                'ExposeHeaders': [
                    'Date', 'x-amz-delete-marker', 'x-amz-version-id'
                ]
            }]
        },
    )

    # get object and assert headers
    url = s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': bucket_name, 'Key': object_key}
    )
    response = requests.get(url, verify=False)
    assert response.headers['Date']
    assert response.headers['x-amz-delete-marker']
    assert response.headers['x-amz-version-id']
    assert not response.headers.get('x-amz-id-2')
    assert not response.headers.get('x-amz-request-id')
    # clean up
    s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': [{'Key': object_key}]})
    s3_client.delete_bucket(Bucket=bucket_name)


def test_s3_invalid_content_md5():
    bucket_name = 'test-bucket-%s' % short_uid()
    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    # put object with invalid content MD5
    for hash in ['__invalid__', '000']:
        raised = False
        try:
            s3_client.put_object(Bucket=bucket_name, Key='test-key',
                Body='something', ContentMD5=hash)
        except Exception:
            raised = True
        if not raised:
            raise Exception('Invalid MD5 hash "%s" should have raised an error' % hash)


def test_s3_upload_download_gzip():
    bucket_name = 'test-bucket-%s' % short_uid()

    s3_client = aws_stack.connect_to_service('s3')
    s3_client.create_bucket(Bucket=bucket_name)

    data = '000000000000000000000000000000'

    # Write contents to memory rather than a file.
    upload_file_object = BytesIO()
    with gzip.GzipFile(fileobj=upload_file_object, mode='w') as filestream:
        filestream.write(data.encode('utf-8'))

    # Upload gzip
    s3_client.put_object(Bucket=bucket_name, Key='test.gz', ContentEncoding='gzip', Body=upload_file_object.getvalue())

    # Download gzip
    downloaded_object = s3_client.get_object(Bucket=bucket_name, Key='test.gz')
    download_file_object = BytesIO(downloaded_object['Body'].read())
    with gzip.GzipFile(fileobj=download_file_object, mode='rb') as filestream:
        downloaded_data = filestream.read().decode('utf-8')

    assert downloaded_data == data, '{} != {}'.format(downloaded_data, data)
