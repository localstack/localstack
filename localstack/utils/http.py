import re
from typing import Dict, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from requests.models import CaseInsensitiveDict

ACCEPT = "accept"


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
        if name.lower().startswith(ACCEPT):
            return name.lower()
        return name

    result = {_normalize(k): v for k, v in headers.items()}
    return result


def add_query_params_to_url(uri: str, query_params: Dict) -> str:
    """
    Add query parameters to the uri.
    :param uri: the base uri it can contains path arguments and query parameters
    :param query_params: new query parameters to be added
    :return: the resulting URL
    """

    # parse the incoming uri
    url = urlparse(uri)

    # parses the query part, if exists, into a dict
    query_dict = dict(parse_qsl(url.query))

    # updates the dict with new query parameters
    query_dict.update(query_params)

    # encodes query parameters
    url_query = urlencode(query_dict)

    # replaces the existing query
    url_parse = url._replace(query=url_query)

    return urlunparse(url_parse)
