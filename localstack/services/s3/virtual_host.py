import copy
import logging
from urllib.parse import urlsplit, urlunsplit

from localstack import config
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.http import Request, Response
from localstack.http.proxy import Proxy
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.s3.utils import S3_VIRTUAL_HOST_FORWARDED_HEADER
from localstack.utils.aws.request_context import AWS_REGION_REGEX

LOG = logging.getLogger(__name__)

# virtual-host style: https://{bucket-name}.s3.{region?}.{domain}:{port?}/{key-name}
# ex: https://{bucket-name}.s3.{region}.localhost.localstack.cloud.com:4566/{key-name}
# ex: https://{bucket-name}.s3.{region}.amazonaws.com/{key-name}
VHOST_REGEX_PATTERN = f"<regex('.*'):bucket>.s3.<regex('({AWS_REGION_REGEX}\\.)?'):region><regex('.*'):domain><regex('(?::\\d+)?'):port>"

# path addressed request with the region in the hostname
# https://s3.{region}.localhost.localstack.cloud.com/{bucket-name}/{key-name}
PATH_WITH_REGION_PATTERN = (
    f"s3.<regex('({AWS_REGION_REGEX}\\.)'):region><regex('.*'):domain><regex('(?::\\d+)?'):port>"
)


class S3VirtualHostProxyHandler:
    """
    A dispatcher Handler which can be used in a ``Router[Handler]`` that proxies incoming requests to a virtual host
    addressed S3 bucket to a path addressed URL, to allow easy routing matching the ASF specs.
    """

    def __call__(self, request: Request, **kwargs) -> Response:
        # TODO region pattern currently not working -> removing it from url
        rewritten_url = self._rewrite_url(url=request.url, **kwargs)

        LOG.debug(f"Rewritten original host url: {request.url} to path-style url: {rewritten_url}")

        forward_to_url = urlsplit(rewritten_url)
        copied_headers = copy.copy(request.headers)
        copied_headers["Host"] = forward_to_url.netloc
        copied_headers[S3_VIRTUAL_HOST_FORWARDED_HEADER] = request.headers["host"]
        # do not preserve the Host when forwarding (to avoid an endless loop)
        with Proxy(
            forward_base_url=config.get_edge_url(),
            preserve_host=False,
        ) as proxy:
            forwarded = proxy.forward(
                request=request, forward_path=forward_to_url.path, headers=copied_headers
            )
        # remove server specific headers that will be added before being returned
        forwarded.headers.pop("date", None)
        forwarded.headers.pop("server", None)
        return forwarded

    @staticmethod
    def _rewrite_url(url: str, domain: str, bucket: str, region: str, port: str, **kwargs) -> str:
        """
        Rewrites the url so that it can be forwarded to moto. Used for vhost-style and for any url that contains the region.

        For vhost style: removes the bucket-name from the host-name and adds it as path
        E.g. https://bucket.s3.localhost.localstack.cloud:4566 -> https://s3.localhost.localstack.cloud:4566/bucket
        E.g. https://bucket.s3.amazonaws.com -> https://s3.localhost.localstack.cloud:4566/bucket

        If the region is contained in the host-name we remove it (for now) as moto cannot handle the region correctly

        :param url: the original url
        :param domain: the domain name
        :param bucket: the bucket name
        :param region: the region name
        :param port: the port number (if specified in the original request URL), or an empty string
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

        # the user can specify whatever domain & port he wants in the Host header
        # we need to make sure we're redirecting the request to our edge URL, possibly s3.localhost.localstack.cloud
        host = f"{domain}:{port}" if port else domain
        edge_host = f"{LOCALHOST_HOSTNAME}:{config.get_edge_port_http()}"
        if host != edge_host:
            netloc = netloc.replace(host, edge_host)

        return urlunsplit((splitted.scheme, netloc, path, splitted.query, splitted.fragment))


@hooks.on_infra_ready(should_load=not config.LEGACY_S3_PROVIDER)
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
