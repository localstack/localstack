import json
from io import BytesIO
from typing import IO, Any, Dict, Optional, Tuple, Union

from werkzeug.datastructures import Headers
from werkzeug.sansio.request import Request as _SansIORequest
from werkzeug.utils import cached_property

from localstack.utils.common import to_bytes
from localstack.utils.strings import to_str


class Request(_SansIORequest):
    """
    An HTTP request object. This is (and should remain) a drop-in replacement for werkzeug's WSGI compliant Request
    objects. It allows simple sans-IO requests outside a web server environment.

    DO NOT add methods that are not also part of werkzeug.wrappers.request.Request object.
    Methods which raise `NotImplementedError` may be implemented as required.
    We use Quart which uses async io to access the IO parts of the request, therefore werkzeug's Request is not used.
    """

    def __init__(
        self,
        method: str = "GET",
        path: str = "",
        headers: Union[Dict, Headers] = None,
        body: Union[bytes, str] = None,
        scheme: str = "http",
        root_path: str = "/",
        query_string: Union[bytes, str] = b"",
        remote_addr: str = None,
        server: Optional[Tuple[str, Optional[int]]] = None,
        raw_path: str = None,
    ):
        if not headers:
            headers = Headers()
        elif isinstance(headers, Headers):
            headers = headers
        else:
            headers = Headers(headers)

        if not body:
            self._body = b""
        elif isinstance(body, str):
            self._body = body.encode("utf-8")
        else:
            self._body = body

        # TODO storing the raw_path here violates the drop-in assumption
        self.raw_path = raw_path

        super(Request, self).__init__(
            method=method,
            scheme=scheme,
            server=server or ("127.0.0.1", None),
            root_path=root_path,
            path=path,
            query_string=to_bytes(query_string),
            headers=headers,
            remote_addr=remote_addr,
        )

    # properties for compatibility with werkzeug wsgi Request wrapper

    @cached_property
    def stream(self) -> IO[bytes]:
        return BytesIO(self._body)

    @cached_property
    def data(self) -> bytes:
        return self.get_data()

    @cached_property
    def json(self) -> Optional[Any]:
        return self.get_json()

    @property
    def form(self):
        raise NotImplementedError

    @property
    def values(self):
        """Naive implementation to parse and return form data.

        The property is invoked by Moto ELB to get the ELB API version in
        `moto.elb.urls.api_version_elb_backend()`
        """
        params = to_str(self.data).split("&")
        output = {}
        for param in params:
            key, value = param.split("=")
            output[key] = value
        return output

    @property
    def files(self):
        raise NotImplementedError

    @cached_property
    def url_root(self) -> str:
        return self.root_url

    def get_data(
        self, cache: bool = True, as_text: bool = False, parse_form_data: bool = False
    ) -> Union[bytes, str]:
        # copied from werkzeug.wrappers.Request
        rv = getattr(self, "_cached_data", None)
        if rv is None:
            if parse_form_data:
                self._load_form_data()
            rv = self.stream.read()
            if cache:
                self._cached_data = rv
        if as_text:
            rv = rv.decode(self.charset, self.encoding_errors)

        return rv  # type: ignore

    _cached_json: Optional[None] = None

    def get_json(
        self, force: bool = False, silent: bool = False, cache: bool = True
    ) -> Optional[Any]:

        if cache and self._cached_json:
            return self._cached_json

        if not (force or self.is_json):
            return None

        try:
            doc = json.loads(self.get_data(cache=cache))
            if cache:
                self._cached_json = doc
            return doc
        except ValueError:
            if silent:
                return None
            raise

    def _load_form_data(self):
        pass

    def close(self) -> None:
        pass


def get_raw_path(request: Request) -> str:
    return request.raw_path
