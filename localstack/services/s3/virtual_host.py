import copy
import logging
from urllib.parse import urlsplit, urlunsplit

from localstack.config import LEGACY_S3_PROVIDER
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.http import Request, Response
from localstack.http.proxy import Proxy
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.s3.utils import S3_VIRTUAL_HOST_FORWARDED_HEADER
from localstack.utils.aws.request_context import AWS_REGION_REGEX

LOG = logging.getLogger(__name__)

# virtual-host style: https://{bucket-name}.s3.{region}.localhost.localstack.cloud.com/{key-name}
VHOST_REGEX_PATTERN = f"<regex('.*'):bucket>.s3.<regex('({AWS_REGION_REGEX}\\.)?'):region>{LOCALHOST_HOSTNAME}<regex('(?::\\d+)?'):port>"

# path addressed request with the region in the hostname
# https://s3.{region}.localhost.localstack.cloud.com/{bucket-name}/{key-name}
PATH_WITH_REGION_PATTERN = (
    f"s3.<regex('({AWS_REGION_REGEX}\\.)'):region>{LOCALHOST_HOSTNAME}<regex('(?::\\d+)?'):port>"
)


class S3VirtualHostProxyHandler:
    """
    A dispatcher Handler which can be used in a ``Router[Handler]`` that proxies incoming requests to a virtual host
    addressed S3 bucket to a path addressed URL, to allow easy routing matching the ASF specs.
    """

    def __init__(self):
        """
        Creates a new Proxy with no forward_base_url configured, it will be changed depending on the incoming request.
        """
        self.proxy = Proxy(forward_base_url="")

    def __call__(self, request: Request, **kwargs) -> Response:
        # TODO region pattern currently not working -> removing it from url
        rewritten_url = self._rewrite_url(request.url, kwargs.get("bucket"), kwargs.get("region"))

        LOG.debug(f"Rewritten original host url: {request.url} to path-style url: {rewritten_url}")

        forward_to_url = urlsplit(rewritten_url)
        copied_headers = copy.copy(request.headers)
        copied_headers["Host"] = forward_to_url.netloc
        copied_headers[S3_VIRTUAL_HOST_FORWARDED_HEADER] = request.headers["host"]
        self.proxy.forward_base_url = f"{forward_to_url.scheme}://{forward_to_url.netloc}"
        forwarded = self.proxy.forward(
            request=request, forward_path=forward_to_url.path, headers=copied_headers
        )
        # remove server specific headers that will be added before being returned
        forwarded.headers.pop("date", None)
        forwarded.headers.pop("server", None)
        return forwarded

    @staticmethod
    def _rewrite_url(url: str, bucket: str, region: str) -> str:
        """
        Rewrites the url so that it can be forwarded to moto. Used for vhost-style and for any url that contains the region.

        For vhost style: removes the bucket-name from the host-name and adds it as path
        E.g. http://my-bucket.s3.localhost.localstack.cloud:4566 -> http://s3.localhost.localstack.cloud:4566/my-bucket

        If the region is contained in the host-name we remove it (for now) as moto cannot handle the region correctly

        :param url: the original url
        :param bucket: the bucket name
        :param region: the region name
        :return: re-written url as string
        """
        splitted = urlsplit(url)
        if splitted.netloc.startswith(f"{bucket}."):
            netloc = splitted.netloc.replace(f"{bucket}.", "")
            path = f"{bucket}{splitted.path}"
        else:
            # we already have a path-style addressing, only need to remove the region
            netloc = splitted.netloc
            path = splitted.path
        # TODO region currently ignored
        if region:
            netloc = netloc.replace(f"{region}", "")

        return urlunsplit((splitted.scheme, netloc, path, splitted.query, splitted.fragment))


@hooks.on_infra_ready(should_load=not LEGACY_S3_PROVIDER)
def register_virtual_host_routes():
    """
    Registers the S3 virtual host handler into the edge router.

    """
    s3_proxy_handler = S3VirtualHostProxyHandler()
    ROUTER.add(
        path="/",
        host=VHOST_REGEX_PATTERN,
        endpoint=s3_proxy_handler,
        defaults={"path": "/"},
    )

    ROUTER.add(
        path="/<path:path>",
        host=VHOST_REGEX_PATTERN,
        endpoint=s3_proxy_handler,
    )

    ROUTER.add(
        path="/<regex('.+'):bucket>",
        host=PATH_WITH_REGION_PATTERN,
        endpoint=s3_proxy_handler,
        defaults={"path": "/"},
    )

    ROUTER.add(
        path="/<regex('.+'):bucket>/<path:path>",
        host=PATH_WITH_REGION_PATTERN,
        endpoint=s3_proxy_handler,
    )
