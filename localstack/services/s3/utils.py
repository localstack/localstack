import base64
import codecs
import datetime
import hashlib
import logging
import re
import zlib
from typing import IO, Any, Dict, Literal, NamedTuple, Optional, Protocol, Tuple, Type, Union
from urllib import parse as urlparser
from zoneinfo import ZoneInfo

import moto.s3.models as moto_s3_models
import xmltodict
from botocore.exceptions import ClientError
from botocore.utils import InvalidArnException
from moto.s3.exceptions import MissingBucket
from moto.s3.models import FakeBucket, FakeDeleteMarker, FakeKey

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.s3 import (
    AccessControlPolicy,
    BucketCannedACL,
    BucketName,
    ChecksumAlgorithm,
    CopyObjectRequest,
    CopySource,
    ETag,
    GetObjectRequest,
    Grant,
    Grantee,
    HeadObjectRequest,
    InvalidArgument,
    InvalidRange,
    InvalidTag,
    LifecycleExpiration,
    LifecycleRule,
    LifecycleRules,
    Metadata,
    MethodNotAllowed,
    NoSuchBucket,
    NoSuchKey,
    ObjectCannedACL,
    ObjectKey,
    ObjectSize,
    ObjectVersionId,
    Owner,
    Permission,
    PreconditionFailed,
    SSEKMSKeyId,
    TaggingHeader,
    TagSet,
)
from localstack.aws.api.s3 import Type as GranteeType
from localstack.aws.connect import connect_to
from localstack.services.s3.constants import (
    ALL_USERS_ACL_GRANTEE,
    AUTHENTICATED_USERS_ACL_GRANTEE,
    LOG_DELIVERY_ACL_GRANTEE,
    S3_CHUNK_SIZE,
    S3_VIRTUAL_HOST_FORWARDED_HEADER,
    SIGNATURE_V2_PARAMS,
    SIGNATURE_V4_PARAMS,
    SYSTEM_METADATA_SETTABLE_HEADERS,
)
from localstack.services.s3.exceptions import InvalidRequest, MalformedXML
from localstack.utils.aws import arns
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import (
    checksum_crc32,
    checksum_crc32c,
    hash_sha1,
    hash_sha256,
    to_bytes,
    to_str,
)
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

checksum_keys = ["ChecksumSHA1", "ChecksumSHA256", "ChecksumCRC32", "ChecksumCRC32C"]

BUCKET_NAME_REGEX = (
    r"(?=^.{3,63}$)(?!^(\d+\.)+\d+$)"
    + r"(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)"
)

REGION_REGEX = r"[a-z]{2}-[a-z]+-[0-9]{1,}"
PORT_REGEX = r"(:[\d]{0,6})?"

TAG_REGEX = re.compile(r"^[\w\s.:/=+\-@]*$")

S3_VIRTUAL_HOSTNAME_REGEX = (  # path based refs have at least valid bucket expression (separated by .) followed by .s3
    r"^(http(s)?://)?((?!s3\.)[^\./]+)\."  # the negative lookahead part is for considering buckets
    r"(((s3(-website)?\.({}\.)?)localhost(\.localstack\.cloud)?)|(localhost\.localstack\.cloud)|"
    r"(s3((-website)|(-external-1))?[\.-](dualstack\.)?"
    r"({}\.)?amazonaws\.com(.cn)?)){}(/[\w\-. ]*)*$"
).format(
    REGION_REGEX, REGION_REGEX, PORT_REGEX
)
_s3_virtual_host_regex = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)


RFC1123 = "%a, %d %b %Y %H:%M:%S GMT"
_gmt_zone_info = ZoneInfo("GMT")


def get_owner_for_account_id(account_id: str):
    """
    This method returns the S3 Owner from the account id. for now, this is hardcoded as it was in moto, but we can then
    extend it to return different values depending on the account ID
    See https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
    :param account_id: the owner account id
    :return: the Owner object containing the DisplayName and owner ID
    """
    return Owner(
        DisplayName="webfile",  # only in certain regions, see above
        ID="75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a",
    )


def extract_bucket_key_version_id_from_copy_source(
    copy_source: CopySource,
) -> tuple[BucketName, ObjectKey, Optional[ObjectVersionId]]:
    """
    Utility to parse bucket name, object key and optionally its versionId. It accepts the CopySource format:
    - <bucket-name/<object-key>?versionId=<version-id>, used for example in CopySource for CopyObject
    :param copy_source: the S3 CopySource to parse
    :return: parsed BucketName, ObjectKey and optionally VersionId
    """
    copy_source_parsed = urlparser.urlparse(copy_source)
    src_bucket, src_key = urlparser.unquote(copy_source_parsed.path).lstrip("/").split("/", 1)
    src_version_id = urlparser.parse_qs(copy_source_parsed.query).get("versionId", [None])[0]

    return src_bucket, src_key, src_version_id


class ChecksumHash(Protocol):
    """
    This Protocol allows proper typing for different kind of hash used by S3 (hashlib.shaX, zlib.crc32 from
    S3CRC32Checksum, and botocore CrtCrc32cChecksum).
    """

    def digest(self) -> bytes:
        ...

    def update(self, value: bytes):
        ...


def get_s3_checksum(algorithm) -> ChecksumHash:
    match algorithm:
        case ChecksumAlgorithm.CRC32:
            return S3CRC32Checksum()

        case ChecksumAlgorithm.CRC32C:
            from botocore.httpchecksum import CrtCrc32cChecksum

            return CrtCrc32cChecksum()

        case ChecksumAlgorithm.SHA1:
            return hashlib.sha1(usedforsecurity=False)

        case ChecksumAlgorithm.SHA256:
            return hashlib.sha256(usedforsecurity=False)

        case _:
            # TODO: check proper error? for now validated client side, need to check server response
            raise InvalidRequest("The value specified in the x-amz-trailer header is not supported")


class S3CRC32Checksum:
    """Implements a unified way of using zlib.crc32 compatibl with hashlib.sha and botocore CrtCrc32cChecksum"""

    __slots__ = ["checksum"]

    def __init__(self):
        self.checksum = None

    def update(self, value: bytes):
        if self.checksum is None:
            self.checksum = zlib.crc32(value)
            return

        self.checksum = zlib.crc32(value, self.checksum)

    def digest(self) -> bytes:
        return self.checksum.to_bytes(4, "big")


class ObjectRange(NamedTuple):
    """
    NamedTuple representing a parsed Range header with the requested S3 object size
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
    """

    content_range: str  # the original Range header
    content_length: int  # the full requested object size
    begin: int  # the start of range
    end: int  # the end of the end


def parse_range_header(range_header: str, object_size: int) -> ObjectRange | None:
    """
    Takes a Range header, and returns a dataclass containing the necessary information to return only a slice of an
    S3 object. If the range header is invalid, we return None so that the request is treated as a regular request.
    :param range_header: a Range header
    :param object_size: the requested S3 object total size
    :return: ObjectRange or None if the Range header is invalid
    """
    last = object_size - 1
    try:
        _, rspec = range_header.split("=")
    except ValueError:
        return None
    if "," in rspec:
        return None

    try:
        begin, end = [int(i) if i else None for i in rspec.split("-")]
    except ValueError:
        # if we can't parse the Range header, S3 just treat the request as a non-range request
        return None

    if (begin is None and end == 0) or (begin is not None and begin > last):
        raise InvalidRange(
            "The requested range is not satisfiable",
            ActualObjectSize=str(object_size),
            RangeRequested=range_header,
        )

    if begin is not None:  # byte range
        end = last if end is None else min(end, last)
    elif end is not None:  # suffix byte range
        begin = object_size - min(end, object_size)
        end = last
    else:
        # Treat as non-range request
        return None

    if begin > min(end, last):
        # Treat as non-range request if after the logic is applied
        return None

    return ObjectRange(
        content_range=f"bytes {begin}-{end}/{object_size}",
        content_length=end - begin + 1,
        begin=begin,
        end=end,
    )


def parse_copy_source_range_header(copy_source_range: str, object_size: int) -> ObjectRange:
    """
    Takes a CopySourceRange parameter, and returns a dataclass containing the necessary information to return only a slice of an
    S3 object. The validation is much stricter than `parse_range_header`
    :param copy_source_range: a CopySourceRange parameter for UploadCopyPart
    :param object_size: the requested S3 object total size
    :raises InvalidArgument if the CopySourceRanger parameter does not follow validation
    :return: ObjectRange
    """
    last = object_size - 1
    try:
        _, rspec = copy_source_range.split("=")
    except ValueError:
        raise InvalidArgument(
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
            ArgumentName="x-amz-copy-source-range",
            ArgumentValue=copy_source_range,
        )
    if "," in rspec:
        raise InvalidArgument(
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
            ArgumentName="x-amz-copy-source-range",
            ArgumentValue=copy_source_range,
        )

    try:
        begin, end = [int(i) if i else None for i in rspec.split("-")]
    except ValueError:
        # if we can't parse the Range header, S3 just treat the request as a non-range request
        raise InvalidArgument(
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
            ArgumentName="x-amz-copy-source-range",
            ArgumentValue=copy_source_range,
        )

    if begin is None or end is None or begin > end:
        raise InvalidArgument(
            "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
            ArgumentName="x-amz-copy-source-range",
            ArgumentValue=copy_source_range,
        )

    if begin > last:
        # Treat as non-range request if after the logic is applied
        raise InvalidRequest(
            "The specified copy range is invalid for the source object size",
        )
    elif end > last:
        raise InvalidArgument(
            f"Range specified is not valid for source object of size: {object_size}",
            ArgumentName="x-amz-copy-source-range",
            ArgumentValue=copy_source_range,
        )

    return ObjectRange(
        content_range=f"bytes {begin}-{end}/{object_size}",
        content_length=end - begin + 1,
        begin=begin,
        end=end,
    )


def get_full_default_bucket_location(bucket_name: BucketName) -> str:
    if config.HOSTNAME_EXTERNAL != config.LOCALHOST:
        host_definition = localstack_host(
            use_hostname_external=True, custom_port=config.get_edge_port_http()
        )
        return f"{config.get_protocol()}://{host_definition.host_and_port()}/{bucket_name}/"
    else:
        host_definition = localstack_host(use_localhost_cloud=True)
        return f"{config.get_protocol()}://{bucket_name}.s3.{host_definition.host_and_port()}/"


def get_object_checksum_for_algorithm(checksum_algorithm: str, data: bytes) -> str:
    match checksum_algorithm:
        case ChecksumAlgorithm.CRC32:
            return checksum_crc32(data)

        case ChecksumAlgorithm.CRC32C:
            return checksum_crc32c(data)

        case ChecksumAlgorithm.SHA1:
            return hash_sha1(data)

        case ChecksumAlgorithm.SHA256:
            return hash_sha256(data)

        case _:
            # TODO: check proper error? for now validated client side, need to check server response
            raise InvalidRequest("The value specified in the x-amz-trailer header is not supported")


def verify_checksum(checksum_algorithm: str, data: bytes, request: Dict):
    # TODO: you don't have to specify the checksum algorithm
    # you can use only the checksum-{algorithm-type} header
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
    key = f"Checksum{checksum_algorithm.upper()}"
    # TODO: is there a message if the header is missing?
    checksum = request.get(key)
    calculated_checksum = get_object_checksum_for_algorithm(checksum_algorithm, data)

    if calculated_checksum != checksum:
        raise InvalidRequest(
            f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
        )


def etag_to_base_64_content_md5(etag: ETag) -> str:
    """
    Convert an ETag, representing an md5 hexdigest (might be quoted), to its base64 encoded representation
    :param etag: an ETag, might be quoted
    :return: the base64 value
    """
    # get the bytes digest from the hexdigest
    byte_digest = codecs.decode(to_bytes(etag.strip('"')), "hex")
    return to_str(base64.b64encode(byte_digest))


def decode_aws_chunked_object(
    stream: IO[bytes],
    buffer: IO[bytes],
    content_length: int,
) -> IO[bytes]:
    """
    Decode the incoming stream encoded in `aws-chunked` format into the provided buffer
    :param stream: the original stream to read, encoded in the `aws-chunked` format
    :param buffer: the buffer where we set the decoded data
    :param content_length: the total maximum length of the original stream, we stop decoding after that
    :return: the provided buffer
    """
    buffer.seek(0)
    buffer.truncate()
    written = 0
    while written < content_length:
        line = stream.readline()
        chunk_length = int(line.split(b";")[0], 16)

        while chunk_length > 0:
            amount = min(chunk_length, S3_CHUNK_SIZE)
            data = stream.read(amount)
            buffer.write(data)

            real_amount = len(data)
            chunk_length -= real_amount
            written += real_amount

        # remove trailing \r\n
        stream.read(2)

    return buffer


def is_presigned_url_request(context: RequestContext) -> bool:
    """
    Detects pre-signed URL from query string parameters
    Return True if any kind of presigned URL query string parameter is encountered
    :param context: the request context from the handler chain
    """
    # Detecting pre-sign url and checking signature
    query_parameters = context.request.args
    return any(p in query_parameters for p in SIGNATURE_V2_PARAMS) or any(
        p in query_parameters for p in SIGNATURE_V4_PARAMS
    )


def is_key_expired(key_object: Union[FakeKey, FakeDeleteMarker]) -> bool:
    if not key_object or isinstance(key_object, FakeDeleteMarker) or not key_object._expiry:
        return False
    return key_object._expiry <= datetime.datetime.now(key_object._expiry.tzinfo)


def is_bucket_name_valid(bucket_name: str) -> bool:
    """
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    return True if re.match(BUCKET_NAME_REGEX, bucket_name) else False


def get_permission_header_name(permission: Permission) -> str:
    return f"x-amz-grant-{permission.replace('_', '-').lower()}"


def get_permission_from_header(capitalized_field: str) -> Permission:
    headers_parts = [part.upper() for part in re.split(r"([A-Z][a-z]+)", capitalized_field) if part]
    return "_".join(headers_parts[1:])


def is_valid_canonical_id(canonical_id: str) -> bool:
    """
    Validate that the string is a hex string with 64 char
    """
    try:
        return int(canonical_id, 16) and len(canonical_id) == 64
    except ValueError:
        return False


def uses_host_addressing(headers: Dict[str, str]) -> bool:
    """
    Determines if the request is targeting S3 with virtual host addressing
    :param headers: the request headers
    :return: whether the request targets S3 with virtual host addressing
    """
    host = headers.get("host", "")

    # try to extract the bucket from the hostname (the "in" check is a minor optimization, as the regex is very greedy)
    return (
        True
        if ".s3" in host and ((match := _s3_virtual_host_regex.match(host)) and match.group(3))
        else False
    )


def get_class_attrs_from_spec_class(spec_class: Type[str]) -> set[str]:
    return {getattr(spec_class, attr) for attr in vars(spec_class) if not attr.startswith("__")}


def get_system_metadata_from_request(request: dict) -> Metadata:
    metadata: Metadata = {}

    for system_metadata_field in SYSTEM_METADATA_SETTABLE_HEADERS:
        if field_value := request.get(system_metadata_field):
            metadata[system_metadata_field] = field_value

    return metadata


def forwarded_from_virtual_host_addressed_request(headers: dict[str, str]) -> bool:
    """
    Determines if the request was forwarded from a v-host addressing style into a path one
    """
    # we can assume that the host header we are receiving here is actually the header we originally received
    # from the client (because the edge service is forwarding the request in memory)
    return S3_VIRTUAL_HOST_FORWARDED_HEADER in headers


def extract_bucket_name_and_key_from_headers_and_path(
    headers: dict[str, str], path: str
) -> tuple[Optional[str], Optional[str]]:
    """
    Extract the bucket name and the object key from a request headers and path. This works with both virtual host
    and path style requests.
    :param headers: the request headers, used to get the Host
    :param path: the request path
    :return: if found, the bucket name and object key
    """
    bucket_name = None
    object_key = None
    host = headers.get("host", "")
    if ".s3" in host:
        vhost_match = _s3_virtual_host_regex.match(host)
        if vhost_match and vhost_match.group(3):
            bucket_name = vhost_match.group(3)
            split = path.split("/", maxsplit=1)
            if len(split) > 1:
                object_key = split[1]
    else:
        path_without_params = path.partition("?")[0]
        split = path_without_params.split("/", maxsplit=2)
        bucket_name = split[1]
        if len(split) > 2:
            object_key = split[2]

    return bucket_name, object_key


def get_bucket_from_moto(
    moto_backend: moto_s3_models.S3Backend, bucket: BucketName
) -> moto_s3_models.FakeBucket:
    # TODO: check authorization for buckets as well?
    try:
        return moto_backend.get_bucket(bucket_name=bucket)
    except MissingBucket:
        raise NoSuchBucket("The specified bucket does not exist", BucketName=bucket)


def get_key_from_moto_bucket(
    moto_bucket: FakeBucket,
    key: ObjectKey,
    version_id: str = None,
    raise_if_delete_marker_method: Literal["GET", "PUT"] = None,
) -> FakeKey | FakeDeleteMarker:
    # TODO: rework the delete marker handling
    # we basically need to re-implement moto `get_object` to account for FakeDeleteMarker
    if version_id is None:
        fake_key = moto_bucket.keys.get(key)
    else:
        for key_version in moto_bucket.keys.getlist(key, default=[]):
            if str(key_version.version_id) == str(version_id):
                fake_key = key_version
                break
        else:
            fake_key = None

    if not fake_key:
        raise NoSuchKey("The specified key does not exist.", Key=key)

    if isinstance(fake_key, FakeDeleteMarker) and raise_if_delete_marker_method:
        # TODO: validate method, but should be PUT in most cases (updating a DeleteMarker)
        match raise_if_delete_marker_method:
            case "GET":
                raise NoSuchKey("The specified key does not exist.", Key=key)
            case "PUT":
                raise MethodNotAllowed(
                    "The specified method is not allowed against this resource.",
                    Method="PUT",
                    ResourceType="DeleteMarker",
                )

    return fake_key


def normalize_bucket_name(bucket_name):
    bucket_name = bucket_name or ""
    bucket_name = bucket_name.lower()
    return bucket_name


def get_bucket_and_key_from_s3_uri(s3_uri: str) -> Tuple[str, Optional[str]]:
    """
    Extracts the bucket name and key from s3 uri
    """
    output_bucket, _, output_key = s3_uri.removeprefix("s3://").partition("/")
    return output_bucket, output_key


def get_bucket_and_key_from_presign_url(presign_url: str) -> Tuple[str, str]:
    """
    Extracts the bucket name and key from s3 presign url
    """
    parsed_url = urlparser.urlparse(presign_url)
    bucket = parsed_url.path.split("/")[1]
    key = "/".join(parsed_url.path.split("/")[2:]).split("?")[0]
    return bucket, key


def _create_invalid_argument_exc(
    message: Union[str, None], name: str, value: str, host_id: str = None
) -> InvalidArgument:
    ex = InvalidArgument(message)
    ex.ArgumentName = name
    ex.ArgumentValue = value
    if host_id:
        ex.HostId = host_id
    return ex


def capitalize_header_name_from_snake_case(header_name: str) -> str:
    return "-".join([part.capitalize() for part in header_name.split("-")])


def get_kms_key_arn(kms_key: str, account_id: str, bucket_region: str = None) -> Optional[str]:
    """
    In S3, the KMS key can be passed as a KeyId or a KeyArn. This method allows to always get the KeyArn from either.
    It can also validate if the key is in the same region, and raise an exception.
    :param kms_key: the KMS key id or ARN
    :param account_id: the bucket account id
    :param bucket_region: the bucket region
    :raise KMS.NotFoundException if the key is not in the same region
    :return: the key ARN if found and enabled
    """
    if not kms_key:
        return None
    try:
        parsed_arn = parse_arn(kms_key)
        key_region = parsed_arn["region"]
        # the KMS key should be in the same region as the bucket, we can raise an exception without calling KMS
        if bucket_region and key_region != bucket_region:
            raise CommonServiceException(
                code="KMS.NotFoundException", message=f"Invalid arn {key_region}"
            )

    except InvalidArnException:
        # if it fails, the passed ID is a UUID with no region data
        key_id = kms_key
        # recreate the ARN manually with the bucket region and bucket owner
        # if the KMS key is cross-account, user should provide an ARN and not a KeyId
        kms_key = arns.kms_key_arn(key_id=key_id, account_id=account_id, region_name=bucket_region)

    return kms_key


# TODO: replace Any by a replacement for S3Bucket, some kind of defined type?
def validate_kms_key_id(kms_key: str, bucket: FakeBucket | Any) -> None:
    """
    Validate that the KMS key used to encrypt the object is valid
    :param kms_key: the KMS key id or ARN
    :param bucket: the targeted bucket
    :raise KMS.DisabledException if the key is disabled
    :raise KMS.NotFoundException if the key is not in the same region or does not exist
    :return: the key ARN if found and enabled
    """
    if hasattr(bucket, "region_name"):
        bucket_region = bucket.region_name
    else:
        bucket_region = bucket.bucket_region

    if hasattr(bucket, "account_id"):
        bucket_account_id = bucket.account_id
    else:
        bucket_account_id = bucket.bucket_account_id

    kms_key_arn = get_kms_key_arn(kms_key, bucket_account_id, bucket_region)

    # the KMS key should be in the same region as the bucket, create the client in the bucket region
    kms_client = connect_to(region_name=bucket_region).kms
    try:
        key = kms_client.describe_key(KeyId=kms_key_arn)
        if not key["KeyMetadata"]["Enabled"]:
            if key["KeyMetadata"]["KeyState"] == "PendingDeletion":
                raise CommonServiceException(
                    code="KMS.KMSInvalidStateException",
                    message=f'{key["KeyMetadata"]["Arn"]} is pending deletion.',
                )
            raise CommonServiceException(
                code="KMS.DisabledException", message=f'{key["KeyMetadata"]["Arn"]} is disabled.'
            )

    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            raise CommonServiceException(
                code="KMS.NotFoundException", message=e.response["Error"]["Message"]
            )
        raise


def create_s3_kms_managed_key_for_region(region_name: str) -> SSEKMSKeyId:
    kms_client = connect_to(region_name=region_name).kms
    key = kms_client.create_key(
        Description="Default key that protects my S3 objects when no other key is defined"
    )

    return key["KeyMetadata"]["Arn"]


def rfc_1123_datetime(src: datetime.datetime) -> str:
    return src.strftime(RFC1123)


def str_to_rfc_1123_datetime(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, RFC1123).replace(tzinfo=_gmt_zone_info)


def iso_8601_datetime_without_milliseconds_s3(
    value: datetime,
) -> Optional[str]:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z") if value else None


def add_expiration_days_to_datetime(user_datatime: datetime.datetime, exp_days: int) -> str:
    """
    This adds expiration days to a datetime, rounding to the next day at midnight UTC.
    :param user_datatime: datetime object
    :param exp_days: provided days
    :return: return a datetime object, rounded to midnight, in string formatted to rfc_1123
    """
    rounded_datetime = user_datatime.replace(
        hour=0, minute=0, second=0, microsecond=0
    ) + datetime.timedelta(days=exp_days + 1)

    return rfc_1123_datetime(rounded_datetime)


def serialize_expiration_header(
    rule_id: str, lifecycle_exp: LifecycleExpiration, last_modified: datetime.datetime
):
    if exp_days := lifecycle_exp.get("Days"):
        # AWS round to the next day at midnight UTC
        exp_date = add_expiration_days_to_datetime(last_modified, exp_days)
    else:
        exp_date = rfc_1123_datetime(lifecycle_exp["Date"])

    return f'expiry-date="{exp_date}", rule-id="{rule_id}"'


def get_lifecycle_rule_from_object(
    lifecycle_conf_rules: LifecycleRules,
    object_key: ObjectKey,
    size: ObjectSize,
    object_tags: dict[str, str],
) -> LifecycleRule:
    for rule in lifecycle_conf_rules:
        if not (expiration := rule.get("Expiration")) or "ExpiredObjectDeleteMarker" in expiration:
            continue

        if not (rule_filter := rule.get("Filter")):
            return rule

        if and_rules := rule_filter.get("And"):
            if all(
                _match_lifecycle_filter(key, value, object_key, size, object_tags)
                for key, value in and_rules.items()
            ):
                return rule

        if any(
            _match_lifecycle_filter(key, value, object_key, size, object_tags)
            for key, value in rule_filter.items()
        ):
            # after validation, we can only one of `Prefix`, `Tag`, `ObjectSizeGreaterThan` or `ObjectSizeLessThan` in
            # the dict. Instead of manually checking, we can iterate of the only key and try to match it
            return rule


def _match_lifecycle_filter(
    filter_key: str,
    filter_value: str | int | dict[str, str],
    object_key: ObjectKey,
    size: ObjectSize,
    object_tags: dict[str, str],
):
    match filter_key:
        case "Prefix":
            return object_key.startswith(filter_value)
        case "Tag":
            return object_tags.get(filter_value.get("Key")) == filter_value.get("Value")
        case "ObjectSizeGreaterThan":
            return size > filter_value
        case "ObjectSizeLessThan":
            return size < filter_value
        case "Tags":  # this is inside the `And` field
            return all(object_tags.get(tag.get("Key")) == tag.get("Value") for tag in filter_value)


def parse_expiration_header(
    expiration_header: str,
) -> tuple[Optional[datetime.datetime], Optional[str]]:
    try:
        header_values = dict(
            (p.strip('"') for p in v.split("=")) for v in expiration_header.split('", ')
        )
        expiration_date = str_to_rfc_1123_datetime(header_values["expiry-date"])
        return expiration_date, header_values["rule-id"]

    except (IndexError, ValueError, KeyError):
        return None, None


def validate_dict_fields(data: dict, required_fields: set, optional_fields: set = None):
    """
    Validate whether the `data` dict contains at least the required fields and not more than the union of the required
    and optional fields
    TODO: we could pass the TypedDict to also use its required/optional properties, but it could be sensitive to
     mistake/changes in the specs and not always right
    :param data: the dict we want to validate
    :param required_fields: a set containing the required fields
    :param optional_fields: a set containing the optional fields
    :return: bool, whether the dict is valid or not
    """
    if optional_fields is None:
        optional_fields = set()
    return (set_fields := set(data)) >= required_fields and set_fields <= (
        required_fields | optional_fields
    )


def parse_tagging_header(tagging_header: TaggingHeader) -> dict:
    try:
        parsed_tags = urlparser.parse_qs(tagging_header, keep_blank_values=True)
        tags: dict[str, str] = {}
        for key, val in parsed_tags.items():
            if len(val) != 1 or not TAG_REGEX.match(key) or not TAG_REGEX.match(val[0]):
                raise InvalidArgument(
                    "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.",
                    ArgumentName="x-amz-tagging",
                    ArgumentValue=tagging_header,
                )
            elif key.startswith("aws:"):
                raise
            tags[key] = val[0]
        return tags

    except ValueError:
        raise InvalidArgument(
            "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates.",
            ArgumentName="x-amz-tagging",
            ArgumentValue=tagging_header,
        )


def validate_tag_set(tag_set: TagSet, type_set: Literal["bucket", "object"] = "bucket"):
    keys = set()
    for tag in tag_set:
        if set(tag) != {"Key", "Value"}:
            raise MalformedXML()

        key = tag["Key"]
        if key in keys:
            raise InvalidTag(
                "Cannot provide multiple Tags with the same key",
                TagKey=key,
            )

        if key.startswith("aws:"):
            if type_set == "bucket":
                message = "System tags cannot be added/updated by requester"
            else:
                message = "Your TagKey cannot be prefixed with aws:"
            raise InvalidTag(
                message,
                TagKey=key,
            )

        if not TAG_REGEX.match(key):
            raise InvalidTag(
                "The TagKey you have provided is invalid",
                TagKey=key,
            )
        elif not TAG_REGEX.match(tag["Value"]):
            raise InvalidTag(
                "The TagValue you have provided is invalid", TagKey=key, TagValue=tag["Value"]
            )

        keys.add(key)


def get_unique_key_id(
    bucket: BucketName, object_key: ObjectKey, version_id: ObjectVersionId
) -> str:
    return f"{bucket}/{object_key}/{version_id or 'null'}"


def get_retention_from_now(days: int = None, years: int = None) -> datetime.datetime:
    """
    This calculates a retention date from now, adding days or years to it
    :param days: provided days
    :param years: provided years, exclusive with days
    :return: return a datetime object
    """
    if not days and not years:
        raise ValueError("Either 'days' or 'years' needs to be provided")
    now = datetime.datetime.now(tz=_gmt_zone_info)
    if days:
        retention = now + datetime.timedelta(days=days)
    else:
        retention = now.replace(year=now.year + years)

    return retention


def get_failed_precondition_copy_source(
    request: CopyObjectRequest, last_modified: datetime.datetime, etag: ETag
) -> Optional[str]:
    """
    Validate if the source object LastModified and ETag matches a precondition, and if it does, return the failed
    precondition
    # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
    :param request: the CopyObjectRequest
    :param last_modified: source object LastModified
    :param etag: source object ETag
    :return str: the failed precondition to raise
    """
    if (cs_if_match := request.get("CopySourceIfMatch")) and etag.strip('"') != cs_if_match.strip(
        '"'
    ):
        return "x-amz-copy-source-If-Match"

    elif (
        cs_if_unmodified_since := request.get("CopySourceIfUnmodifiedSince")
    ) and last_modified > cs_if_unmodified_since:
        return "x-amz-copy-source-If-Unmodified-Since"

    elif (cs_if_none_match := request.get("CopySourceIfNoneMatch")) and etag.strip(
        '"'
    ) == cs_if_none_match.strip('"'):
        return "x-amz-copy-source-If-None-Match"

    elif (
        cs_if_modified_since := request.get("CopySourceIfModifiedSince")
    ) and last_modified < cs_if_modified_since < datetime.datetime.now(tz=_gmt_zone_info):
        return "x-amz-copy-source-If-Modified-Since"


def validate_failed_precondition(
    request: GetObjectRequest | HeadObjectRequest, last_modified: datetime.datetime, etag: ETag
) -> None:
    """
    Validate if the object LastModified and ETag matches a precondition, and if it does, return the failed
    precondition
    :param request: the GetObjectRequest or HeadObjectRequest
    :param last_modified: S3 object LastModified
    :param etag: S3 object ETag
    :raises PreconditionFailed
    :raises NotModified, 304 with an empty body
    """
    precondition_failed = None
    if (if_match := request.get("IfMatch")) and etag != if_match.strip('"'):
        precondition_failed = "If-Match"

    elif (
        if_unmodified_since := request.get("IfUnmodifiedSince")
    ) and last_modified > if_unmodified_since:
        precondition_failed = "If-Unmodified-Since"

    if precondition_failed:
        raise PreconditionFailed(
            "At least one of the pre-conditions you specified did not hold",
            Condition=precondition_failed,
        )

    if ((if_none_match := request.get("IfNoneMatch")) and etag == if_none_match.strip('"')) or (
        (if_modified_since := request.get("IfModifiedSince"))
        and last_modified < if_modified_since < datetime.datetime.now(tz=_gmt_zone_info)
    ):
        raise CommonServiceException(
            message="Not Modified",
            code="NotModified",
            status_code=304,
        )


def get_canned_acl(
    canned_acl: BucketCannedACL | ObjectCannedACL, owner: Owner
) -> AccessControlPolicy:
    """
    Return the proper Owner and Grants from a CannedACL
    See https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl
    :param canned_acl: an S3 CannedACL
    :param owner: the current owner of the bucket or object
    :return: an AccessControlPolicy containing the Grants and Owner
    """
    owner_grantee = Grantee(**owner, Type=GranteeType.CanonicalUser)
    grants = [Grant(Grantee=owner_grantee, Permission=Permission.FULL_CONTROL)]

    match canned_acl:
        case ObjectCannedACL.private:
            pass  # no other permissions
        case ObjectCannedACL.public_read:
            grants.append(Grant(Grantee=ALL_USERS_ACL_GRANTEE, Permission=Permission.READ))

        case ObjectCannedACL.public_read_write:
            grants.append(Grant(Grantee=ALL_USERS_ACL_GRANTEE, Permission=Permission.READ))
            grants.append(Grant(Grantee=ALL_USERS_ACL_GRANTEE, Permission=Permission.WRITE))
        case ObjectCannedACL.authenticated_read:
            grants.append(
                Grant(Grantee=AUTHENTICATED_USERS_ACL_GRANTEE, Permission=Permission.READ)
            )
        case ObjectCannedACL.bucket_owner_read:
            pass  # TODO: bucket owner ACL
        case ObjectCannedACL.bucket_owner_full_control:
            pass  # TODO: bucket owner ACL
        case ObjectCannedACL.aws_exec_read:
            pass  # TODO: bucket owner, EC2 Read
        case BucketCannedACL.log_delivery_write:
            grants.append(Grant(Grantee=LOG_DELIVERY_ACL_GRANTEE, Permission=Permission.READ_ACP))
            grants.append(Grant(Grantee=LOG_DELIVERY_ACL_GRANTEE, Permission=Permission.WRITE))

    return AccessControlPolicy(Owner=owner, Grants=grants)


def create_redirect_for_post_request(
    base_redirect: str, bucket: BucketName, object_key: ObjectKey, etag: ETag
):
    """
    POST requests can redirect if successful. It will take the URL provided and append query string parameters
    (key, bucket and ETag). It needs to be a full URL.
    :param base_redirect: the URL provided for redirection
    :param bucket: bucket name
    :param object_key: object key
    :param etag: key ETag
    :return: the URL provided with the new appended query string parameters
    """
    parts = urlparser.urlparse(base_redirect)
    if not parts.netloc:
        raise ValueError("The provided URL is not valid")
    queryargs = urlparser.parse_qs(parts.query)
    queryargs["key"] = [object_key]
    queryargs["bucket"] = [bucket]
    queryargs["etag"] = [etag]
    redirect_queryargs = urlparser.urlencode(queryargs, doseq=True)
    newparts = (
        parts.scheme,
        parts.netloc,
        parts.path,
        parts.params,
        redirect_queryargs,
        parts.fragment,
    )
    return urlparser.urlunparse(newparts)


def parse_post_object_tagging_xml(tagging: str) -> Optional[dict]:
    try:
        tag_set = {}
        tags = xmltodict.parse(tagging)
        xml_tags = tags.get("Tagging", {}).get("TagSet", {}).get("Tag", [])
        if not xml_tags:
            # if the Tagging does not respect the schema, just return
            return
        if not isinstance(xml_tags, list):
            xml_tags = [xml_tags]
        for tag in xml_tags:
            tag_set[tag["Key"]] = tag["Value"]

        return tag_set

    except Exception:
        raise MalformedXML()
