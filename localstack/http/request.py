from io import BytesIO
from typing import IO, TYPE_CHECKING, Dict, Mapping, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlencode, urlparse

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment

from werkzeug.datastructures import Headers, MultiDict
from werkzeug.test import encode_multipart
from werkzeug.wrappers.request import Request as WerkzeugRequest

from localstack.utils import strings


def dummy_wsgi_environment(
    method: str = "GET",
    path: str = "",
    headers: Optional[Union[Dict, Headers]] = None,
    body: Optional[Union[bytes, str, IO[bytes]]] = None,
    scheme: str = "http",
    root_path: str = "/",
    query_string: Optional[str] = None,
    remote_addr: Optional[str] = None,
    server: Optional[Tuple[str, Optional[int]]] = None,
    raw_uri: Optional[str] = None,
) -> "WSGIEnvironment":
    """
    Creates a dummy WSGIEnvironment that represents a standalone sans-IO HTTP requests.

    See https://wsgi.readthedocs.io/en/latest/definitions.html#standard-environ-keys

    :param method: The HTTP request method (such as GET or POST)
    :param path: The remainder of the request URL's path. This may be an empty string, if the
        request URL targets the application root and does not have a trailing slash.
    :param headers: optional HTTP headers
    :param body: the body of the request
    :param scheme: the scheme (http or https)
    :param root_path: The initial portion of the request URL's path that corresponds to the
        application object.
    :param query_string: The portion of the request URL that follows the “?”, if any. May be
        empty or absent.
    :param remote_addr: The address making the request
    :param server: The server (tuple of server name and port)
    :param raw_uri: The original path that may contain url encoded path elements.
    :return: A WSGIEnvironment dictionary
    """

    # Standard environ keys
    environ = {
        "REQUEST_METHOD": method,
        # prepare the paths for the "WSGI decoding dance" done by werkzeug
        "SCRIPT_NAME": unquote(quote(root_path.rstrip("/")), "latin-1"),
        "PATH_INFO": unquote(quote(path), "latin-1"),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "QUERY_STRING": query_string or "",
    }

    if raw_uri:
        if query_string:
            raw_uri += "?" + query_string
        environ["RAW_URI"] = raw_uri
        environ["REQUEST_URI"] = environ["RAW_URI"]

    if server:
        environ["SERVER_NAME"] = server[0]
        if server[1]:
            environ["SERVER_PORT"] = str(server[1])
        else:
            environ["SERVER_PORT"] = "80"
    else:
        environ["SERVER_NAME"] = "127.0.0.1"
        environ["SERVER_PORT"] = "80"

    if remote_addr:
        environ["REMOTE_ADDR"] = remote_addr

    if headers:
        set_environment_headers(environ, headers)

    if not body or isinstance(body, (str, bytes)):
        data = strings.to_bytes(body) if body else b""
        wsgi_input = BytesIO(data)
        if "CONTENT_LENGTH" not in environ:
            # try to determine content length from body
            environ["CONTENT_LENGTH"] = str(len(data))
    else:
        wsgi_input = body

    # WSGI environ keys
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = scheme
    environ["wsgi.input"] = wsgi_input
    environ["wsgi.input_terminated"] = True
    environ["wsgi.errors"] = BytesIO()
    environ["wsgi.multithread"] = True
    environ["wsgi.multiprocess"] = False
    environ["wsgi.run_once"] = False

    return environ


def set_environment_headers(environ: "WSGIEnvironment", headers: Union[Dict, Headers]):
    # Collect all the headers to set
    # (this might be is accessing the environment, this needs to be done before removing the items from the env)
    new_headers = {}
    for k, v in headers.items():
        name = k.upper().replace("-", "_")

        if name not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            name = f"HTTP_{name}"

        val = v
        if name in new_headers:
            val = new_headers[name] + "," + val

        new_headers[name] = val

    # Clear the HTTP headers in the env
    header_keys = [name for name in environ if name.startswith("HTTP_")]
    for name in header_keys:
        environ.pop(name, None)

    # Set the new headers in the env
    for k, v in new_headers.items():
        environ[k] = v


class Request(WerkzeugRequest):
    """
    An HTTP request object. This is (and should remain) a drop-in replacement for werkzeug's WSGI
    compliant Request objects. It allows simple sans-IO requests outside a web server environment.

    DO NOT add methods that are not also part of werkzeug.wrappers.request.Request object.
    """

    def __init__(
        self,
        method: str = "GET",
        path: str = "",
        headers: Union[Mapping, Headers] = None,
        body: Union[bytes, str] = None,
        scheme: str = "http",
        root_path: str = "/",
        query_string: Union[bytes, str] = b"",
        remote_addr: str = None,
        server: Optional[Tuple[str, Optional[int]]] = None,
        raw_path: str = None,
    ):
        # decode query string if necessary (latin-1 is what werkzeug would expect)
        query_string = strings.to_str(query_string, "latin-1")

        # create the WSGIEnvironment dictionary that represents this request
        environ = dummy_wsgi_environment(
            method=method,
            path=path,
            headers=headers,
            body=body,
            scheme=scheme,
            root_path=root_path,
            query_string=query_string,
            remote_addr=remote_addr,
            server=server,
            raw_uri=raw_path,
        )

        super(Request, self).__init__(environ)

        # restore originally passed headers:
        # werkzeug normally provides read-only access to headers set in the WSGIEnvironment through the EnvironHeaders
        # class, here we make them mutable again. moreover, WSGI header encoding conflicts with RFC2616. see this github
        # issue for a discussion: https://github.com/pallets/werkzeug/issues/940
        headers = Headers(headers)
        # these two headers are treated separately in the WSGI environment, so we extract them if necessary
        for h in ["content-length", "content-type"]:
            if h not in headers and h in self.headers:
                headers[h] = self.headers[h]
        self.headers = headers

    @classmethod
    def application(cls, *args):
        # werkzeug's application decorator assumes its Request constructor signature, which our Request doesn't support.
        # using ``application`` from our request therefore creates runtime errors. this makes sure no one runs into
        # these problems. if we want to support it, we need to create compatibility with werkzeug's Request constructor
        raise NotImplementedError


def get_raw_path(request) -> str:
    """
    Returns the raw_path inside the request without the query string. The request can either be a Quart Request
    object (that encodes the raw path in request.scope['raw_path']) or a Werkzeug WSGI request (that encodes the raw
    URI in request.environ['RAW_URI']).

    :param request: the request object
    :return: the raw path if any
    """
    if hasattr(request, "environ"):
        # werkzeug/flask request (already a string, and contains the query part)
        # we need to parse it, because the RAW_URI can contain a full URL if it is specified in the HTTP request
        return urlparse(request.environ.get("RAW_URI", request.path)).path

    if hasattr(request, "scope"):
        # quart request raw_path comes as bytes, and without the query part
        return request.scope.get("raw_path", request.path).decode("utf-8")

    raise ValueError("cannot extract raw path from request object %s" % request)


def get_full_raw_path(request) -> str:
    """
    Returns the full raw request path (with original URL encoding), including the query string.
    This is _not_ equal to request.url, since there the path section would be url-encoded while the query part will be
    (partly) url-decoded.
    """
    query_str = f"?{strings.to_str(request.query_string)}" if request.query_string else ""
    raw_path = f"{get_raw_path(request)}{query_str}"
    return raw_path


def get_raw_base_url(request: Request) -> str:
    """
    Returns the base URL (with original URL encoding). This does not include the query string.
    This is the encoding-preserving equivalent to `request.base_url`.
    """
    return get_raw_current_url(
        request.scheme, request.host, request.root_path, get_raw_path(request)
    )


def get_raw_current_url(
    scheme: str,
    host: str,
    root_path: Optional[str] = None,
    path: Optional[str] = None,
    query_string: Optional[bytes] = None,
) -> str:
    """
    `werkzeug.sansio.utils.get_current_url` implementation without
    any encoding dances.
    The given paths and query string are directly used without any encodings
    (to avoid any double encodings).
    It can be used to recreate the raw URL for a request.

    :param scheme: The protocol the request used, like ``"https"``.
    :param host: The host the request was made to. See :func:`get_host`.
    :param root_path: Prefix that the application is mounted under. This
        is prepended to ``path``.
    :param path: The path part of the URL after ``root_path``.
    :param query_string: The portion of the URL after the "?".
    """
    url = [scheme, "://", host]

    if root_path is None:
        url.append("/")
        return "".join(url)

    url.append(root_path.rstrip("/"))
    url.append("/")

    if path is None:
        return "".join(url)

    url.append(path.lstrip("/"))

    if query_string:
        url.append("?")
        url.append(query_string)

    return "".join(url)


def restore_payload(request: Request) -> bytes:
    """
    This method takes a request and restores the original payload from it even after it has been consumed. A werkzeug
    request consumes form/multipart data from the stream, and here we are serializing it back to a request a client
    could make . This is a useful method to have when we are proxying requests, i.e., create outgoing requests from
    incoming requests that were subject to previous parsing.

    TODO: this construct is not great and will definitely be a source of trouble. but something like this will
      inevitably become the the basis of proxying werkzeug requests. The alternative is to build our own request object
      that memoizes the original payload before parsing.
    """
    if request.shallow:
        return b""

    data = request.data

    if request.method != "POST":
        return data

    # TODO: check how request that encode both files and form are really serialized (not sure this works this way)

    if request.form:
        data += urlencode(list(request.form.items(multi=True))).encode("utf-8")

    if request.files:
        boundary = request.content_type.split("=")[1]

        fields = MultiDict()
        fields.update(request.form)
        fields.update(request.files)

        _, data_files = encode_multipart(fields, boundary)
        data += data_files

    return data
