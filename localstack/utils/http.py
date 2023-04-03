import logging
import os
import re
import traceback
from typing import Dict, Optional, Union
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

import requests
from requests.models import CaseInsensitiveDict, Response

from localstack import config

from .strings import to_str

# chunk size for file downloads
DOWNLOAD_CHUNK_SIZE = 1024 * 1024

ACCEPT = "accept"
LOG = logging.getLogger(__name__)


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


def add_path_parameters_to_url(uri: str, path_params: list):
    url = urlparse(uri)
    last_character = (
        "/" if (len(url.path) == 0 or url.path[-1] != "/") and len(path_params) > 0 else ""
    )
    new_path = url.path + last_character + "/".join(path_params)
    return urlunparse(url._replace(path=new_path))


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


def make_http_request(
    url: str, data: Union[bytes, str] = None, headers: Dict[str, str] = None, method: str = "GET"
) -> Response:
    return requests.request(
        url=url, method=method, headers=headers, data=data, auth=NetrcBypassAuth(), verify=False
    )


class NetrcBypassAuth(requests.auth.AuthBase):
    def __call__(self, r):
        return r


class _RequestsSafe:
    """Wrapper around requests library, which can prevent it from verifying
    SSL certificates or reading credentials from ~/.netrc file"""

    verify_ssl = True

    def __getattr__(self, name):
        method = requests.__dict__.get(name.lower())
        if not method:
            return method

        def _wrapper(*args, **kwargs):
            if "auth" not in kwargs:
                kwargs["auth"] = NetrcBypassAuth()
            url = kwargs.get("url") or (args[1] if name == "request" else args[0])
            if not self.verify_ssl and url.startswith("https://") and "verify" not in kwargs:
                kwargs["verify"] = False
            return method(*args, **kwargs)

        return _wrapper


# create safe_requests instance
safe_requests = _RequestsSafe()


def parse_request_data(method: str, path: str, data=None, headers=None) -> Dict:
    """Extract request data either from query string as well as request body (e.g., for POST)."""
    result = {}
    headers = headers or {}
    content_type = headers.get("Content-Type", "")

    # add query params to result
    parsed_path = urlparse(path)
    result.update(parse_qs(parsed_path.query))

    # add params from url-encoded payload
    if method in ["POST", "PUT", "PATCH"] and (not content_type or "form-" in content_type):
        # content-type could be either "application/x-www-form-urlencoded" or "multipart/form-data"
        try:
            params = parse_qs(to_str(data or ""))
            result.update(params)
        except Exception:
            pass  # probably binary / JSON / non-URL encoded payload - ignore

    # select first elements from result lists (this is assuming we are not using parameter lists!)
    result = {k: v[0] for k, v in result.items()}
    return result


def get_proxies() -> Dict[str, str]:
    proxy_map = {}
    if config.OUTBOUND_HTTP_PROXY:
        proxy_map["http"] = config.OUTBOUND_HTTP_PROXY
    if config.OUTBOUND_HTTPS_PROXY:
        proxy_map["https"] = config.OUTBOUND_HTTPS_PROXY
    return proxy_map


def download(
    url: str,
    path: str,
    verify_ssl: bool = True,
    timeout: float = None,
    request_headers: Optional[dict] = None,
):
    """Downloads file at url to the given path. Raises TimeoutError if the optional timeout (in secs) is reached."""

    # make sure we're creating a new session here to enable parallel file downloads
    s = requests.Session()
    proxies = get_proxies()
    if proxies:
        s.proxies.update(proxies)

    # Use REQUESTS_CA_BUNDLE path. If it doesn't exist, use the method provided settings.
    # Note that a value that is not False, will result to True and will get the bundle file.
    _verify = os.getenv("REQUESTS_CA_BUNDLE", verify_ssl)

    r = None
    try:
        r = s.get(url, stream=True, verify=_verify, timeout=timeout, headers=request_headers)
        # check status code before attempting to read body
        if not r.ok:
            raise Exception("Failed to download %s, response code %s" % (url, r.status_code))

        total = 0
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        LOG.debug(
            "Starting download from %s to %s (%s bytes)", url, path, r.headers.get("Content-Length")
        )
        with open(path, "wb") as f:
            iter_length = 0
            iter_limit = 1000000  # print a log line for every 1MB chunk
            for chunk in r.iter_content(DOWNLOAD_CHUNK_SIZE):
                total += len(chunk)
                iter_length += len(chunk)
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
                else:
                    LOG.debug("Empty chunk %s (total %s) from %s", chunk, total, url)
                if iter_length >= iter_limit:
                    LOG.debug("Written %s bytes (total %s) to %s", iter_length, total, path)
                    iter_length = 0
            f.flush()
            os.fsync(f)
        if os.path.getsize(path) == 0:
            LOG.warning("Zero bytes downloaded from %s, retrying", url)
            download(url, path, verify_ssl)
            return
        LOG.debug(
            "Done downloading %s, response code %s, total bytes %d", url, r.status_code, total
        )
    except requests.exceptions.ReadTimeout as e:
        raise TimeoutError(f"Timeout ({timeout}) reached on download: {url} - {e}")
    finally:
        if r is not None:
            r.close()
        s.close()


def download_github_artifact(url: str, target_file: str, timeout: int = None):
    """Download file from main URL or fallback URL (to avoid firewall errors if github.com is blocked).
    Optionally allows to define a timeout in seconds."""

    def do_download(
        download_url: str, request_headers: Optional[dict] = None, print_error: bool = False
    ):
        try:
            download(download_url, target_file, timeout=timeout, request_headers=request_headers)
            return True
        except Exception as e:
            if print_error:
                LOG.info(
                    "Unable to download Github artifact from from %s to %s: %s %s"
                    % (url, target_file, e, traceback.format_exc())
                )

    # if a GitHub API token is set, use it to avoid rate limiting issues
    gh_token = os.environ.get("GITHUB_API_TOKEN")
    gh_auth_headers = None
    if gh_token:
        gh_auth_headers = {"authorization": f"Bearer {gh_token}"}
    result = do_download(url, request_headers=gh_auth_headers)
    if not result:
        # TODO: use regex below to allow different branch names than "master"
        url = url.replace("https://github.com", "https://cdn.jsdelivr.net/gh")
        # The URL structure is https://cdn.jsdelivr.net/gh/user/repo@branch/file.js
        url = url.replace("/raw/master/", "@master/")
        # Do not send the GitHub auth token to the CDN
        do_download(url, print_error=True)


# TODO move to aws_responses.py?
def replace_response_content(response, pattern, replacement):
    content = to_str(response.content or "")
    response._content = re.sub(pattern, replacement, content)
