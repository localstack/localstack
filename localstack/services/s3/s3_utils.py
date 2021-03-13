import re

S3_STATIC_WEBSITE_HOST_REGEX = r'^(.+).s3-website.localhost.localstack.cloud(:[\d]{0,6})?$'
S3_VIRTUAL_HOSTNAME_REGEX = r'^(http(s)?:\/\/)?([^.]+)\.s3(-website)?\.localhost\.localstack\.cloud(:[\d]{0,6})?$'

BUCKET_NAME_REGEX = (r'(?=^.{3,63}$)(?!^(\d+\.)+\d+$)' +
    r'(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)')


def is_static_website(headers):
    """
    Determine if the incoming request is for s3 static website hosting
    returns True if the host matches website regex
    returns False if the host does not matches website regex
    """
    pattern = re.compile(S3_STATIC_WEBSITE_HOST_REGEX)
    match = pattern.match(headers.get('host', ''))
    if match:
        return True
    else:
        return False


def uses_host_addressing(headers):
    """
    Determines if the bucket is using host based addressing style or path based
    """
    pattern = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)
    match = pattern.match(headers.get('host', ''))
    if match and match.group(3):
        return True
    else:
        return False


def extract_bucket_name(headers, path):
    """
    Extract the bucket name
    if using host based addressing it's extracted from host header
    if using path based addressing it's extracted form the path
    """
    bucket_name = None
    if uses_host_addressing(headers):
        pattern = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)
        match = pattern.match(headers.get('host', ''))

        if match and match.group(3):
            bucket_name = match.group(3)
    else:
        bucket_name = path.split('/', 2)[1]
    return bucket_name if bucket_name else None


def extract_key_name(headers, path):
    """
    Extract the key name from the path depending on addressing_style
    """
    key_name = None
    if uses_host_addressing(headers):
        split = path.split('/', 1)
        if len(split) > 1:
            key_name = split[1]
    else:
        split = path.split('/', 2)
        if len(split) > 2:
            key_name = split[2]

    return key_name if key_name else None


def validate_bucket_name(bucket_name):
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    return True if re.match(BUCKET_NAME_REGEX, bucket_name) else False
