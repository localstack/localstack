import logging
import boto3
from botocore.exceptions import ClientError

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id='',
        aws_secret_access_key='',
        region_name='ap-south-1',
        endpoint_url='http://localhost:4566'
    )

def bucket_exists(bucket_name):
    """Determine whether bucket_name exists and the user has permission to access it
    :param bucket_name: string
    :return: True if the referenced bucket_name exists, otherwise False
    """
    s3 = boto3.client('s3')
    try:
        response = s3.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.debug(e)
        return False
    return True

def create_bucket(bucket_name):
    s3_client = get_s3_client()
    logging.basicConfig(level=logging.DEBUG,format='%(levelname)s: %(asctime)s: %(message)s')
    if bucket_exists(bucket_name):
        print(f'{bucket_name} exists and you have permission to access it.')
    else:
        s3_client.create_bucket(Bucket=bucket_name)


                     
if __name__ == '__main__':
    bucket_objects = create_bucket('test-bucket-3')
    
    