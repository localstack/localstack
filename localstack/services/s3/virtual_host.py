import copy
import logging
from urllib.parse import urlsplit, urlunsplit

from localstack.config import LEGACY_S3_PROVIDER
from localstack.constants import LOCALHOST, LOCALHOST_HOSTNAME
from localstack.http import Request, Response
from localstack.http.proxy import Proxy
from localstack.runtime import hooks
from localstack.services.edge import ROUTER
from localstack.services.s3.utils import S3_VIRTUAL_HOST_FORWARDED_HEADER
from localstack.utils.aws.request_context import AWS_REGION_REGEX
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

# virtual-host style: https://{bucket-name}.s3.{region}.localhost.localstack.cloud.com/{key-name}
VHOST_REGEX_PATTERN = "<regex('.*'):bucket>.s3.<regex('({aws_region_regex}\\.)?'):region>{hostname}<regex('(?::\\d+)?'):port>"

# path addressed request with the region in the hostname
# https://s3.{region}.localhost.localstack.cloud.com/{bucket-name}/{key-name}
PATH_WITH_REGION_PATTERN = (
    "s3.<regex('({aws_region_regex}\\.)'):region>{hostname}<regex('(?::\\d+)?'):port>"
)


class S3VirtualHostProxyHandler:
    """
    A dispatcher Handler which can be used in a ``Router[Handler]`` that proxies incoming requests to a virtual host
    addressed S3 bucket to a path addressed URL, to allow easy routing matching the ASF specs.
    """

    def __call__(self, request: Request, **kwargs) -> Response:
        # TODO region pattern currently not working -> removing it from url
        rewritten_url = self._rewrite_url(request.url, kwargs.get("bucket"), kwargs.get("region"))
        LOG.debug(f"Rewritten original host url: {request.url} to path-style url: {rewritten_url}")

        forward_to_url = urlsplit(rewritten_url)
        copied_headers = copy.copy(request.headers)
        copied_headers["Host"] = forward_to_url.netloc
        copied_headers[S3_VIRTUAL_HOST_FORWARDED_HEADER] = request.headers["host"]
        # do not preserve the Host when forwarding (to avoid an endless loop)
        with Proxy(
            forward_base_url=f"{forward_to_url.scheme}://{forward_to_url.netloc}",
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
    def _rewrite_url(url: str, bucket: str, region: str) -> str:
        """
        Rewrites the url so that it can be forwarded to moto. Used for vhost-style and for any url that contains the region.

        For vhost style: removes the bucket-name from the host-name and adds it as path
        E.g. http://my-bucket.s3.localhost.localstack.cloud:4566 -> http://s3.localhost.localstack.cloud:4566/my-bucket

        If the region is contained in the host-name we remove it (for now) as moto cannot handle the region correctly

        If the url contains a customised hostname, for example if the user sets `HOSTNAME_EXTERNAL` then re-write the
        host to localhost.localstack.cloud since the request is coming from inside LocalStack itself, and `HOSTNAME_EXTERNAL`
        may not be resolvable.

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

        # if the user specifies a custom hostname for LocalStack, this name may not be resolvable by
        # LocalStack. We are proxying the request to ourself, so replace their custom hostname with
        # `localhost.localstack.cloud` which also matches the PATH matchers.
        host_definition = localstack_host(use_hostname_external=True)
        if host_definition.host != LOCALHOST:
            netloc = netloc.replace(host_definition.host, LOCALHOST_HOSTNAME)

        return urlunsplit((splitted.scheme, netloc, path, splitted.query, splitted.fragment))


@hooks.on_infra_ready(should_load=not LEGACY_S3_PROVIDER)
def register_virtual_host_routes():
    """
    Registers the S3 virtual host handler into the edge router.

    """
    s3_proxy_handler = S3VirtualHostProxyHandler()
    host_definition = localstack_host(use_hostname_external=True)
    # Add additional routes if the user specifies a custom HOSTNAME_EXTERNAL
    # as we should match on these routes, and also match on localhost.localstack.cloud
    # to maintain backwards compatibility.
    if host_definition.host != LOCALHOST:
        ROUTER.add(
            path="/",
            host=VHOST_REGEX_PATTERN.format(
                aws_region_regex=AWS_REGION_REGEX,
                hostname=host_definition.host,
            ),
            endpoint=s3_proxy_handler,
            defaults={"path": "/"},
        )

        ROUTER.add(
            path="/<path:path>",
            host=VHOST_REGEX_PATTERN.format(
                aws_region_regex=AWS_REGION_REGEX,
                hostname=host_definition.host,
            ),
            endpoint=s3_proxy_handler,
        )

        ROUTER.add(
            path="/<regex('.+'):bucket>",
            host=PATH_WITH_REGION_PATTERN.format(
                aws_region_regex=AWS_REGION_REGEX,
                hostname=host_definition.host,
            ),
            endpoint=s3_proxy_handler,
            defaults={"path": "/"},
        )

        ROUTER.add(
            path="/<regex('.+'):bucket>/<path:path>",
            host=PATH_WITH_REGION_PATTERN.format(
                aws_region_regex=AWS_REGION_REGEX,
                hostname=host_definition.host,
            ),
            endpoint=s3_proxy_handler,
        )

    ROUTER.add(
        path="/",
        host=VHOST_REGEX_PATTERN.format(
            aws_region_regex=AWS_REGION_REGEX,
            hostname=LOCALHOST_HOSTNAME,
        ),
        endpoint=s3_proxy_handler,
        defaults={"path": "/"},
    )

    ROUTER.add(
        path="/<path:path>",
        host=VHOST_REGEX_PATTERN.format(
            aws_region_regex=AWS_REGION_REGEX,
            hostname=LOCALHOST_HOSTNAME,
        ),
        endpoint=s3_proxy_handler,
    )

    ROUTER.add(
        path="/<regex('.+'):bucket>",
        host=PATH_WITH_REGION_PATTERN.format(
            aws_region_regex=AWS_REGION_REGEX,
            hostname=LOCALHOST_HOSTNAME,
        ),
        endpoint=s3_proxy_handler,
        defaults={"path": "/"},
    )

    ROUTER.add(
        path="/<regex('.+'):bucket>/<path:path>",
        host=PATH_WITH_REGION_PATTERN.format(
            aws_region_regex=AWS_REGION_REGEX,
            hostname=LOCALHOST_HOSTNAME,
        ),
        endpoint=s3_proxy_handler,
    )
