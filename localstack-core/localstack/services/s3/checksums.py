# Code ported/inspired from https://github.com/aliyun/aliyun-oss-python-sdk/blob/master/oss2/crc64_combine.py
# This code implements checksum combinations: the ability to get the full checksum of an object with the checksums of
# its parts.
import sys

_CRC64NVME_POLYNOMIAL = 0xAD93D23594C93659
_CRC32_POLYNOMIAL = 0x104C11DB7
_CRC32C_POLYNOMIAL = 0x1EDC6F41
_CRC64_XOR_OUT = 0xFFFFFFFFFFFFFFFF
_CRC32_XOR_OUT = 0xFFFFFFFF
_GF2_DIM_64 = 64
_GF2_DIM_32 = 32


def gf2_matrix_square(square, mat):
    for n in range(len(mat)):
        square[n] = gf2_matrix_times(mat, mat[n])


def gf2_matrix_times(mat, vec):
    summary = 0
    mat_index = 0

    while vec:
        if vec & 1:
            summary ^= mat[mat_index]

        vec >>= 1
        mat_index += 1

    return summary


def _combine(
    poly: int,
    size_bits: int,
    init_crc: int,
    rev: bool,
    xor_out: int,
    crc1: int,
    crc2: int,
    len2: int,
) -> bytes:
    if len2 == 0:
        return _encode_to_bytes(crc1, size_bits)

    even = [0] * size_bits
    odd = [0] * size_bits

    crc1 ^= init_crc ^ xor_out

    if rev:
        # put operator for one zero bit in odd
        odd[0] = poly  # CRC-64 polynomial
        row = 1
        for n in range(1, size_bits):
            odd[n] = row
            row <<= 1
    else:
        row = 2
        for n in range(0, size_bits - 1):
            odd[n] = row
            row <<= 1
        odd[size_bits - 1] = poly

    gf2_matrix_square(even, odd)

    gf2_matrix_square(odd, even)

    while True:
        gf2_matrix_square(even, odd)
        if len2 & 1:
            crc1 = gf2_matrix_times(even, crc1)
        len2 >>= 1
        if len2 == 0:
            break

        gf2_matrix_square(odd, even)
        if len2 & 1:
            crc1 = gf2_matrix_times(odd, crc1)
        len2 >>= 1

        if len2 == 0:
            break

    crc1 ^= crc2

    return _encode_to_bytes(crc1, size_bits)


def _encode_to_bytes(crc: int, size_bits: int) -> bytes:
    if size_bits == 64:
        return crc.to_bytes(8, byteorder="big")
    elif size_bits == 32:
        return crc.to_bytes(4, byteorder="big")
    else:
        raise ValueError("size_bites must be 32 or 64")


def _bitrev(x: int, n: int):
    # Bit reverse the input value.
    x = int(x)
    y = 0
    for i in range(n):
        y = (y << 1) | (x & 1)
        x = x >> 1
    if ((1 << n) - 1) <= sys.maxsize:
        return int(y)
    return y


def _verify_params(size_bits: int, init_crc: int, xor_out: int):
    """
    The following function validates the parameters of the CRC, namely, poly, and initial/final XOR values.
    It returns the size of the CRC (in bits), and "sanitized" initial/final XOR values.
    """
    mask = (1 << size_bits) - 1

    # Adjust the initial CRC to the correct data type (unsigned value).
    init_crc = int(init_crc) & mask
    if mask <= sys.maxsize:
        init_crc = int(init_crc)

    # Similar for XOR-out value.
    xor_out = int(xor_out) & mask
    if mask <= sys.maxsize:
        xor_out = int(xor_out)

    return size_bits, init_crc, xor_out


def create_combine_function(poly: int, size_bits: int, init_crc=~0, rev=True, xor_out=0):
    """
    The function returns the proper function depending on the checksum algorithm wanted.
    Example, for the CRC64NVME function, you need to pass the proper polynomial, its size (64), and the proper XOR_OUT
    (taken for the botocore/httpchecksums.py file).
    :param poly: the CRC polynomial used (each algorithm has its own, for ex. CRC32C is called Castagnioli)
    :param size_bits: the size of the algorithm, 32 for CRC32 and 64 for CRC64
    :param init_crc: the init_crc, always 0 in our case
    :param rev: reversing the polynomial, true in our case as well
    :param xor_out: value used to initialize the register as we don't specify init_crc
    :return:
    """
    size_bits, init_crc, xor_out = _verify_params(size_bits, init_crc, xor_out)

    mask = (1 << size_bits) - 1
    if rev:
        poly = _bitrev(poly & mask, size_bits)
    else:
        poly = poly & mask

    def combine_func(crc1: bytes | int, crc2: bytes | int, len2: int):
        if isinstance(crc1, bytes):
            crc1 = int.from_bytes(crc1, byteorder="big")
        if isinstance(crc2, bytes):
            crc2 = int.from_bytes(crc2, byteorder="big")
        return _combine(poly, size_bits, init_crc ^ xor_out, rev, xor_out, crc1, crc2, len2)

    return combine_func


combine_crc64_nvme = create_combine_function(
    _CRC64NVME_POLYNOMIAL, 64, init_crc=0, xor_out=_CRC64_XOR_OUT
)
combine_crc32 = create_combine_function(_CRC32_POLYNOMIAL, 32, init_crc=0, xor_out=_CRC32_XOR_OUT)
combine_crc32c = create_combine_function(_CRC32C_POLYNOMIAL, 32, init_crc=0, xor_out=_CRC32_XOR_OUT)


__all__ = ["combine_crc32", "combine_crc32c", "combine_crc64_nvme"]
