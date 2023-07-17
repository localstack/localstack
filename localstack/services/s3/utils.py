import datetime
import hashlib
import logging
import re
import zlib
from typing import IO, Dict, Literal, Optional, Tuple, Union
from urllib import parse as urlparser
from zoneinfo import ZoneInfo

import moto.s3.models as moto_s3_models
from botocore.exceptions import ClientError
from botocore.utils import InvalidArnException
from moto.s3.exceptions import MissingBucket
from moto.s3.models import FakeBucket, FakeDeleteMarker, FakeKey
from moto.s3.utils import clean_key_name

from localstack.aws.api import CommonServiceException, RequestContext, ServiceException
from localstack.aws.api.s3 import (
    BucketName,
    ChecksumAlgorithm,
    InvalidArgument,
    LifecycleExpiration,
    LifecycleRule,
    LifecycleRules,
    MethodNotAllowed,
    NoSuchBucket,
    NoSuchKey,
    ObjectKey,
)
from localstack.aws.connect import connect_to
from localstack.services.s3.constants import (
    S3_CHUNK_SIZE,
    S3_VIRTUAL_HOST_FORWARDED_HEADER,
    SIGNATURE_V2_PARAMS,
    SIGNATURE_V4_PARAMS,
    VALID_CANNED_ACLS_BUCKET,
)
from localstack.utils.aws import arns
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import checksum_crc32, checksum_crc32c, hash_sha1, hash_sha256

LOG = logging.getLogger(__name__)

checksum_keys = ["ChecksumSHA1", "ChecksumSHA256", "ChecksumCRC32", "ChecksumCRC32C"]

BUCKET_NAME_REGEX = (
    r"(?=^.{3,63}$)(?!^(\d+\.)+\d+$)"
    + r"(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)"
)

REGION_REGEX = r"[a-z]{2}-[a-z]+-[0-9]{1,}"
PORT_REGEX = r"(:[\d]{0,6})?"

S3_VIRTUAL_HOSTNAME_REGEX = (  # path based refs have at least valid bucket expression (separated by .) followed by .s3
    r"^(http(s)?://)?((?!s3\.)[^\./]+)\."  # the negative lookahead part is for considering buckets
    r"(((s3(-website)?\.({}\.)?)localhost(\.localstack\.cloud)?)|(localhost\.localstack\.cloud)|"
    r"(s3((-website)|(-external-1))?[\.-](dualstack\.)?"
    r"({}\.)?amazonaws\.com(.cn)?)){}(/[\w\-. ]*)*$"
).format(
    REGION_REGEX, REGION_REGEX, PORT_REGEX
)

PATTERN_UUID = re.compile(
    r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
)


RFC1123 = "%a, %d %b %Y %H:%M:%S GMT"


class InvalidRequest(ServiceException):
    code: str = "InvalidRequest"
    sender_fault: bool = False
    status_code: int = 400


def extract_bucket_key_version_id_from_copy_source(
    copy_source: str,
) -> tuple[BucketName, ObjectKey, Optional[str]]:
    copy_source_parsed = urlparser.urlparse(copy_source)
    src_bucket, src_key = urlparser.unquote(copy_source_parsed.path).lstrip("/").split("/", 1)
    src_version_id = urlparser.parse_qs(copy_source_parsed.query).get("versionId", [None])[0]
    return src_bucket, src_key, src_version_id


def get_s3_checksum(algorithm):
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


def get_object_checksum_for_algorithm(checksum_algorithm: str, data: bytes):
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


def is_canned_acl_bucket_valid(canned_acl: str) -> bool:
    return canned_acl in VALID_CANNED_ACLS_BUCKET


def get_header_name(capitalized_field: str) -> str:
    headers_parts = re.split(r"([A-Z][a-z]+)", capitalized_field)
    return f"x-amz-{'-'.join([part.lower() for part in headers_parts if part])}"


def is_valid_canonical_id(canonical_id: str) -> bool:
    """
    Validate that the string is a hex string with 64 char
    """
    try:
        return int(canonical_id, 16) and len(canonical_id) == 64
    except ValueError:
        return False


def forwarded_from_virtual_host_addressed_request(headers: Dict[str, str]) -> bool:
    """
    Determines if the request was forwarded from a v-host addressing style into a path one
    """
    # we can assume that the host header we are receiving here is actually the header we originally received
    # from the client (because the edge service is forwarding the request in memory)
    match = re.match(S3_VIRTUAL_HOSTNAME_REGEX, headers.get(S3_VIRTUAL_HOST_FORWARDED_HEADER, ""))

    # checks whether there is a bucket name. This is sort of hacky
    return True if match and match.group(3) else False


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
    clean_key = clean_key_name(key)
    if version_id is None:
        fake_key = moto_bucket.keys.get(clean_key)
    else:
        for key_version in moto_bucket.keys.getlist(clean_key, default=[]):
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


def validate_kms_key_id(kms_key: str, bucket: FakeBucket) -> None:
    """
    Validate that the KMS key used to encrypt the object is valid
    :param kms_key: the KMS key id or ARN
    :param bucket: the targeted bucket
    :raise KMS.DisabledException if the key is disabled
    :raise KMS.NotFoundException if the key is not in the same region or does not exist
    :return: the key ARN if found and enabled
    """
    try:
        parsed_arn = parse_arn(kms_key)
        key_region = parsed_arn["region"]
        # the KMS key should be in the same region as the bucket, we can raise an exception without calling KMS
        if key_region != bucket.region_name:
            raise CommonServiceException(
                code="KMS.NotFoundException", message=f"Invalid arn {key_region}"
            )

    except InvalidArnException:
        # if it fails, the passed ID is a UUID with no region data
        key_id = kms_key
        # recreate the ARN manually with the bucket region and bucket owner
        # if the KMS key is cross-account, user should provide an ARN and not a KeyId
        kms_key = arns.kms_key_arn(
            key_id=key_id, account_id=bucket.account_id, region_name=bucket.region_name
        )

    # the KMS key should be in the same region as the bucket, create the client in the bucket region
    kms_client = connect_to(region_name=bucket.region_name).kms
    try:
        key = kms_client.describe_key(KeyId=kms_key)
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


def rfc_1123_datetime(src: datetime.datetime) -> str:
    return src.strftime(RFC1123)


def str_to_rfc_1123_datetime(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, RFC1123).replace(tzinfo=ZoneInfo("GMT"))


def serialize_expiration_header(
    rule_id: str, lifecycle_exp: LifecycleExpiration, last_modified: datetime.datetime
):
    if not (exp_date := lifecycle_exp.get("Date")):
        exp_days = lifecycle_exp.get("Days")
        # AWS round to the next day at midnight UTC
        exp_date = last_modified.replace(
            hour=0, minute=0, second=0, microsecond=0
        ) + datetime.timedelta(days=exp_days + 1)
    return f'expiry-date="{rfc_1123_datetime(exp_date)}", rule-id="{rule_id}"'


def get_lifecycle_rule_from_object(
    lifecycle_conf_rules: LifecycleRules, moto_object: FakeKey, object_tags: dict[str, str]
) -> LifecycleRule:
    for rule in lifecycle_conf_rules:
        if "Expiration" not in rule:
            continue

        if not (rule_filter := rule.get("Filter")):
            return rule

        if and_rules := rule_filter.get("And"):
            if all(
                _match_lifecycle_filter(key, value, moto_object, object_tags)
                for key, value in and_rules.items()
            ):
                return rule

        if any(
            _match_lifecycle_filter(key, value, moto_object, object_tags)
            for key, value in rule_filter.items()
        ):
            # after validation, we can only one of `Prefix`, `Tag`, `ObjectSizeGreaterThan` or `ObjectSizeLessThan` in
            # the dict. Instead of manually checking, we can iterate of the only key and try to match it
            return rule


def _match_lifecycle_filter(
    filter_key: str, filter_value, moto_object: FakeKey, object_tags: dict[str, str]
):
    match filter_key:
        case "Prefix":
            return moto_object.name.startswith(filter_value)
        case "Tag":
            return object_tags.get(filter_value.get("Key")) == filter_value.get("Value")
        case "ObjectSizeGreaterThan":
            return moto_object.size > filter_value
        case "ObjectSizeLessThan":
            return moto_object.size < filter_value
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


def validate_dict_fields(data: dict, required_fields: set, optional_fields: set):
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
    return (set_fields := set(data)) >= required_fields and set_fields <= (
        required_fields | optional_fields
    )
