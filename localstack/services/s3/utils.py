from typing import Union

from localstack.aws.api import ServiceException
from localstack.aws.api.s3 import (  # BucketName,; ContentMD5,
    ChecksumAlgorithm,
    ChecksumCRC32,
    ChecksumCRC32C,
    ChecksumSHA1,
    ChecksumSHA256,
)
from localstack.utils.strings import checksum_crc32, checksum_crc32c, hash_sha1, hash_sha256

Checksums = Union[ChecksumSHA1, ChecksumSHA256, ChecksumCRC32, ChecksumCRC32C]


class InvalidRequest(ServiceException):
    """The lifecycle configuration does not exist."""

    code: str = "InvalidRequest"
    sender_fault: bool = False
    status_code: int = 404


def verify_checksum(data: bytes, checksum: Checksums, checksum_algorithm: ChecksumAlgorithm):

    match checksum_algorithm:
        case ChecksumAlgorithm.CRC32:
            calculated_checksum = checksum_crc32(data)

        case ChecksumAlgorithm.CRC32C:
            calculated_checksum = checksum_crc32c(data)

        case ChecksumAlgorithm.SHA1:
            calculated_checksum = hash_sha1(data)

        case ChecksumAlgorithm.SHA256:
            calculated_checksum = hash_sha256(data)

        case _:
            # TODO: check proper error? for now is validated client side, need to check server response
            raise InvalidRequest("The value specified in the x-amz-trailer header is not supported")

    if calculated_checksum != checksum:
        raise InvalidRequest(
            f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
        )
