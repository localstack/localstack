import json
from localstack.utils.aws import aws_stack

TEST_BUCKET_NAME_WITH_POLICY = 'test_bucket_policy_1'


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
