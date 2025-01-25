import base64

import pytest

from localstack.services.s3 import checksums
from localstack.services.s3.utils import S3CRC32Checksum


@pytest.mark.parametrize("checksum_type", ["CRC32", "CRC32C", "CRC64NVME"])
def test_s3_checksum_combine(checksum_type):
    match checksum_type:
        case "CRC32":
            checksum = S3CRC32Checksum
            combine_function = checksums.combine_crc32
        case "CRC32C":
            from botocore.httpchecksum import CrtCrc32cChecksum

            checksum = CrtCrc32cChecksum
            combine_function = checksums.combine_crc32c
        case "CRC64NVME":
            from botocore.httpchecksum import CrtCrc64NvmeChecksum

            checksum = CrtCrc64NvmeChecksum
            combine_function = checksums.combine_crc64_nvme
        case _:
            raise f"Bad parameter value! {checksum_type}"

    part_1 = b"123"
    part_2 = b"456"
    part_3 = b"789"

    checksum_1 = checksum()
    checksum_2 = checksum()
    checksum_3 = checksum()

    checksum_1.update(part_1)
    checksum_2.update(part_2)
    checksum_3.update(part_3)

    # those are the validation checksums
    checksum_sum_1 = checksum()
    checksum_sum_total = checksum()

    checksum_sum_1.update(part_1 + part_2)
    checksum_sum_total.update(part_1 + part_2 + part_3)

    digest_1 = checksum_1.digest()
    digest_2 = checksum_2.digest()
    digest_3 = checksum_3.digest()

    digest_sum_1 = checksum_sum_1.digest()
    digest_sum_total = checksum_sum_total.digest()

    crc_partial_1 = base64.b64encode(digest_sum_1).decode()
    crc_total = base64.b64encode(digest_sum_total).decode()

    # we combine the part 1 and part 2
    combined = combine_function(digest_1, digest_2, len(part_2))
    assert combined == digest_sum_1
    assert base64.b64encode(combined).decode() == crc_partial_1

    # we now combine the partial checksum of 1 + 2 with the last part
    combined_partial_and_last_part = combine_function(combined, digest_3, len(part_3))
    assert combined_partial_and_last_part == digest_sum_total
    assert base64.b64encode(combined_partial_and_last_part).decode() == crc_total
