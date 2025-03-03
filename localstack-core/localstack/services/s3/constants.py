from localstack.aws.api.s3 import (
    ChecksumAlgorithm,
    Grantee,
    Permission,
    PublicAccessBlockConfiguration,
    ServerSideEncryption,
    ServerSideEncryptionByDefault,
    ServerSideEncryptionRule,
    StorageClass,
)
from localstack.aws.api.s3 import Type as GranteeType

S3_VIRTUAL_HOST_FORWARDED_HEADER = "x-s3-vhost-forwarded-for"

S3_UPLOAD_PART_MIN_SIZE = 5242880
"""
This is minimum size allowed by S3 when uploading more than one part for a Multipart Upload, except for the last part
"""

# These 2 values have been the historical hardcoded values for S3 credentials if needing to validate S3 pre-signed URLs
DEFAULT_PRE_SIGNED_ACCESS_KEY_ID = "test"
DEFAULT_PRE_SIGNED_SECRET_ACCESS_KEY = "test"

AUTHENTICATED_USERS_ACL_GROUP = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
ALL_USERS_ACL_GROUP = "http://acs.amazonaws.com/groups/global/AllUsers"
LOG_DELIVERY_ACL_GROUP = "http://acs.amazonaws.com/groups/s3/LogDelivery"

VALID_ACL_PREDEFINED_GROUPS = {
    AUTHENTICATED_USERS_ACL_GROUP,
    ALL_USERS_ACL_GROUP,
    LOG_DELIVERY_ACL_GROUP,
}

VALID_GRANTEE_PERMISSIONS = {
    Permission.FULL_CONTROL,
    Permission.READ,
    Permission.READ_ACP,
    Permission.WRITE,
    Permission.WRITE_ACP,
}

VALID_STORAGE_CLASSES = [
    StorageClass.STANDARD,
    StorageClass.STANDARD_IA,
    StorageClass.GLACIER,
    StorageClass.GLACIER_IR,
    StorageClass.REDUCED_REDUNDANCY,
    StorageClass.ONEZONE_IA,
    StorageClass.INTELLIGENT_TIERING,
    StorageClass.DEEP_ARCHIVE,
]

ARCHIVES_STORAGE_CLASSES = [
    StorageClass.GLACIER,
    StorageClass.DEEP_ARCHIVE,
]

CHECKSUM_ALGORITHMS: list[ChecksumAlgorithm] = [
    ChecksumAlgorithm.SHA1,
    ChecksumAlgorithm.SHA256,
    ChecksumAlgorithm.CRC32,
    ChecksumAlgorithm.CRC32C,
    ChecksumAlgorithm.CRC64NVME,
]

# response header overrides the client may request
ALLOWED_HEADER_OVERRIDES = {
    "ResponseContentType": "ContentType",
    "ResponseContentLanguage": "ContentLanguage",
    "ResponseExpires": "Expires",
    "ResponseCacheControl": "CacheControl",
    "ResponseContentDisposition": "ContentDisposition",
    "ResponseContentEncoding": "ContentEncoding",
}

# Whether to enable S3 bucket policy enforcement in moto - currently disabled, as some recent CDK versions
# are creating bucket policies that enforce aws:SecureTransport, which makes the CDK deployment fail.
# TODO: potentially look into making configurable
ENABLE_MOTO_BUCKET_POLICY_ENFORCEMENT = False


SYSTEM_METADATA_SETTABLE_HEADERS = [
    "CacheControl",
    "ContentDisposition",
    "ContentEncoding",
    "ContentLanguage",
    "ContentType",
]

# params are required in presigned url
SIGNATURE_V2_PARAMS = ["Signature", "Expires", "AWSAccessKeyId"]

SIGNATURE_V4_PARAMS = [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
]

# The chunk size to use when iterating over and writing to S3 streams.
# chosen as middle ground between memory usage and amount of iterations over the S3 object body
# This is AWS recommended size when uploading chunks
# https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
S3_CHUNK_SIZE = 65536

DEFAULT_BUCKET_ENCRYPTION = ServerSideEncryptionRule(
    ApplyServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
        SSEAlgorithm=ServerSideEncryption.AES256,
    ),
    BucketKeyEnabled=False,
)

DEFAULT_PUBLIC_BLOCK_ACCESS = PublicAccessBlockConfiguration(
    BlockPublicAcls=True,
    BlockPublicPolicy=True,
    RestrictPublicBuckets=True,
    IgnorePublicAcls=True,
)

AUTHENTICATED_USERS_ACL_GRANTEE = Grantee(URI=AUTHENTICATED_USERS_ACL_GROUP, Type=GranteeType.Group)
ALL_USERS_ACL_GRANTEE = Grantee(URI=ALL_USERS_ACL_GROUP, Type=GranteeType.Group)
LOG_DELIVERY_ACL_GRANTEE = Grantee(URI=LOG_DELIVERY_ACL_GROUP, Type=GranteeType.Group)
