import re
from localstack.constants import S3_VIRTUAL_HOSTNAME, S3_STATIC_WEBSITE_HOSTNAME
from localstack import config

REGION_REGEX = r'[a-z]{2}-[a-z]+-[0-9]{1,}'
PORT_REGEX = r'(:[\d]{0,6})?'
S3_STATIC_WEBSITE_HOST_REGEX = r'^([^.]+)\.s3-website\.localhost\.localstack\.cloud(:[\d]{0,6})?$'
S3_VIRTUAL_HOSTNAME_REGEX = (r'^(http(s)?://)?([^\.]+)\.s3((-website)|(-external-1))?[\.-](dualstack\.)?'
                             r'((localhost\.localstack\.cloud)|'
                             r'(({}\.)?amazonaws\.com(.cn)?)){}$'.format(REGION_REGEX, PORT_REGEX))
BUCKET_NAME_REGEX = (r'(?=^.{3,63}$)(?!^(\d+\.)+\d+$)' +
    r'(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)')


def is_static_website(headers):
    """
    Determine if the incoming request is for s3 static website hosting
    returns True if the host matches website regex
    returns False if the host does not matches website regex
    """
    return bool(re.match(S3_STATIC_WEBSITE_HOST_REGEX, headers.get('host', '')))


def uses_host_addressing(headers):
    """
    Determines if the bucket is using host based addressing style or path based
    """
    # we can assume that the host header we are receiving here is actually the header we originally received
    # from the client (because the edge service is forwarding the request in memory)
    match = re.match(S3_VIRTUAL_HOSTNAME_REGEX, headers.get('host', ''))
    return True if match and match.group(3) else False


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


def get_bucket_hostname(bucket_name):
    """
    Get bucket name for addressing style host
    """
    return '%s.%s:%s' % (bucket_name, S3_VIRTUAL_HOSTNAME, config.EDGE_PORT)


def get_bucket_website_hostname(bucket_name):
    """
    Get bucket name for addressing style host for website hosting
    """
    return '%s.%s:%s' % (bucket_name, S3_STATIC_WEBSITE_HOSTNAME, config.EDGE_PORT)
