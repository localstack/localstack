import re
from typing import Dict, Union

from requests.models import CaseInsensitiveDict


def uses_chunked_encoding(response):
    return response.headers.get("Transfer-Encoding", "").lower() == "chunked"


def parse_chunked_data(data):
    """Parse the body of an HTTP message transmitted with chunked transfer encoding."""
    data = (data or "").strip()
    chunks = []
    while data:
        length = re.match(r"^([0-9a-zA-Z]+)\r\n.*", data)
        if not length:
            break
        length = length.group(1).lower()
        length = int(length, 16)
        data = data.partition("\r\n")[2]
        chunks.append(data[:length])
        data = data[length:].strip()
    return "".join(chunks)


def create_chunked_data(data, chunk_size: int = 80):
    dl = len(data)
    ret = ""
    for i in range(dl // chunk_size):
        ret += "%s\r\n" % (hex(chunk_size)[2:])
        ret += "%s\r\n\r\n" % (data[i * chunk_size : (i + 1) * chunk_size])

    if len(data) % chunk_size != 0:
        ret += "%s\r\n" % (hex(len(data) % chunk_size)[2:])
        ret += "%s\r\n" % (data[-(len(data) % chunk_size) :])

    ret += "0\r\n\r\n"
    return ret


def canonicalize_headers(headers: Union[Dict, CaseInsensitiveDict]) -> Dict:
    if not headers:
        return headers

    def _normalize(name):
        return name.lower()

    result = {_normalize(k): v for k, v in headers.items()}
    return result
