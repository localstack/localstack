import base64
import binascii
import hashlib
import itertools
import random
import re
import string
import uuid
import zlib
from typing import Dict, List, Union

from localstack.config import DEFAULT_ENCODING

_unprintables = (
    range(0x00, 0x09),
    range(0x0A, 0x0A),
    range(0x0B, 0x0D),
    range(0x0E, 0x20),
    range(0xD800, 0xE000),
    range(0xFFFE, 0x10000),
)

# regular expression for unprintable characters
# Based on https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
#     #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
REGEX_UNPRINTABLE_CHARS = re.compile(
    f"[{re.escape(''.join(map(chr, itertools.chain(*_unprintables))))}]"
)


def to_str(obj: Union[str, bytes], encoding: str = DEFAULT_ENCODING, errors="strict") -> str:
    """If ``obj`` is an instance of ``binary_type``, return
    ``obj.decode(encoding, errors)``, otherwise return ``obj``"""
    return obj.decode(encoding, errors) if isinstance(obj, bytes) else obj


def to_bytes(obj: Union[str, bytes], encoding: str = DEFAULT_ENCODING, errors="strict") -> bytes:
    """If ``obj`` is an instance of ``text_type``, return
    ``obj.encode(encoding, errors)``, otherwise return ``obj``"""
    return obj.encode(encoding, errors) if isinstance(obj, str) else obj


def truncate(data: str, max_length: int = 100) -> str:
    data = str(data or "")
    return ("%s..." % data[:max_length]) if len(data) > max_length else data


def is_string(s, include_unicode=True, exclude_binary=False):
    if isinstance(s, bytes) and exclude_binary:
        return False
    if isinstance(s, str):
        return True
    if include_unicode and isinstance(s, str):
        return True
    return False


def is_string_or_bytes(s):
    return is_string(s) or isinstance(s, str) or isinstance(s, bytes)


def is_base64(s):
    regex = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    return is_string(s) and re.match(regex, s)


_re_camel_to_snake_case = re.compile("((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))")


def camel_to_snake_case(string: str) -> str:
    return _re_camel_to_snake_case.sub(r"_\1", string).replace("__", "_").lower()


def snake_to_camel_case(string: str, capitalize_first: bool = True) -> str:
    components = string.split("_")
    start_idx = 0 if capitalize_first else 1
    components = [x.title() for x in components[start_idx:]]
    return "".join(components)


def hyphen_to_snake_case(string: str) -> str:
    return string.replace("-", "_")


def canonicalize_bool_to_str(val: bool) -> str:
    return "true" if str(val).lower() == "true" else "false"


def convert_to_printable_chars(value: Union[List, Dict, str]) -> str:
    """Removes all unprintable characters from the given string."""
    from localstack.utils.objects import recurse_object

    if isinstance(value, (dict, list)):

        def _convert(obj, **kwargs):
            if isinstance(obj, str):
                return convert_to_printable_chars(obj)
            return obj

        return recurse_object(value, _convert)

    result = REGEX_UNPRINTABLE_CHARS.sub("", value)
    return result


def first_char_to_lower(s: str) -> str:
    return s and "%s%s" % (s[0].lower(), s[1:])


def first_char_to_upper(s: str) -> str:
    return s and "%s%s" % (s[0].upper(), s[1:])


def str_to_bool(value):
    """Return the boolean value of the given string, or the verbatim value if it is not a string"""
    if isinstance(value, str):
        true_strings = ["true", "True"]
        return value in true_strings
    return value


def str_insert(string, index, content):
    """Insert a substring into an existing string at a certain index."""
    return "%s%s%s" % (string[:index], content, string[index:])


def str_remove(string, index, end_index=None):
    """Remove a substring from an existing string at a certain from-to index range."""
    end_index = end_index or (index + 1)
    return "%s%s" % (string[:index], string[end_index:])


def str_startswith_ignore_case(value: str, prefix: str) -> bool:
    return value[: len(prefix)].lower() == prefix.lower()


def short_uid() -> str:
    return str(uuid.uuid4())[0:8]


def short_uid_from_seed(seed: str) -> str:
    hash = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    truncated_hash = hash[:32]
    return str(uuid.UUID(truncated_hash))[0:8]


def long_uid() -> str:
    return str(uuid.uuid4())


def md5(string: Union[str, bytes]) -> str:
    m = hashlib.md5()
    m.update(to_bytes(string))
    return m.hexdigest()


def checksum_crc32(string: Union[str, bytes]) -> str:
    bytes = to_bytes(string)
    checksum = zlib.crc32(bytes)
    return base64.b64encode(checksum.to_bytes(4, "big")).decode()


def checksum_crc32c(string: Union[str, bytes]):
    # import botocore locally here to avoid a dependency of the CLI to botocore
    from botocore.httpchecksum import CrtCrc32cChecksum

    checksum = CrtCrc32cChecksum()
    checksum.update(to_bytes(string))
    return base64.b64encode(checksum.digest()).decode()


def checksum_crc64nvme(string: Union[str, bytes]):
    # import botocore locally here to avoid a dependency of the CLI to botocore
    from botocore.httpchecksum import CrtCrc64NvmeChecksum

    checksum = CrtCrc64NvmeChecksum()
    checksum.update(to_bytes(string))
    return base64.b64encode(checksum.digest()).decode()


def hash_sha1(string: Union[str, bytes]) -> str:
    digest = hashlib.sha1(to_bytes(string)).digest()
    return base64.b64encode(digest).decode()


def hash_sha256(string: Union[str, bytes]) -> str:
    digest = hashlib.sha256(to_bytes(string)).digest()
    return base64.b64encode(digest).decode()


def base64_to_hex(b64_string: str) -> bytes:
    return binascii.hexlify(base64.b64decode(b64_string))


def base64_decode(data: Union[str, bytes]) -> bytes:
    """Decode base64 data - with optional padding, and able to handle urlsafe encoding (containing -/_)."""
    data = to_str(data)
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data = to_str(data) + "=" * (4 - missing_padding)
    if "-" in data or "_" in data:
        return base64.urlsafe_b64decode(data)
    return base64.b64decode(data)


def get_random_hex(length: int) -> str:
    return "".join(random.choices(string.hexdigits[:16], k=length)).lower()


def remove_leading_extra_slashes(input: str) -> str:
    """
    Remove leading extra slashes from the given input string.
    Example: '///foo/bar' -> '/foo/bar'
    """
    return re.sub(r"^/+", "/", input)


def prepend_with_slash(input: str) -> str:
    """
    Prepend a slash `/` to a given string if it does not have one already.
    """
    if not input.startswith("/"):
        return f"/{input}"
    return input


def key_value_pairs_to_dict(pairs: str, delimiter: str = ",", separator: str = "=") -> dict:
    """
    Converts a string of key-value pairs to a dictionary.

    Args:
        pairs (str): A string containing key-value pairs separated by a delimiter.
        delimiter (str): The delimiter used to separate key-value pairs (default is comma ',').
        separator (str): The separator between keys and values (default is '=').

    Returns:
        dict: A dictionary containing the parsed key-value pairs.
    """
    splits = [split_pair.partition(separator) for split_pair in pairs.split(delimiter)]
    return {key.strip(): value.strip() for key, _, value in splits}


def token_generator(item: str) -> str:
    base64_bytes = base64.b64encode(item.encode("utf-8"))
    token = base64_bytes.decode("utf-8")
    return token
