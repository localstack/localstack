import logging
import re
from re import Match
from typing import Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.http import Response
from localstack.http.proxy import forward
from localstack.http.request import Request, restore_payload
from localstack.utils.aws.aws_responses import calculate_crc32
from localstack.utils.aws.aws_stack import is_internal_call_context
from localstack.utils.aws.request_context import extract_region_from_headers
from localstack.utils.run import to_str
from localstack.utils.strings import to_bytes

LOG = logging.getLogger(__name__)


class ArnPartitionRewriteHandler(Handler):
    """
    Intercepts requests and responses and tries to adjust the partitions in ARNs within the
    intercepted requests.
    For incoming requests, the default partition is set ("aws").
    For outgoing responses, the partition is adjusted based on the region in the ARN, or by the
    default region if the ARN does not contain a region.
    This listener is used to support other partitions than the default "aws" partition (f.e.
    aws-us-gov) without
    rewriting all the cases where the ARN is parsed or constructed within LocalStack or moto.
    In other words, this listener makes sure that internally the ARNs are always in the partition
    "aws", while the client gets ARNs with the proper partition.
    """

    # Partition which should be statically set for incoming requests
    DEFAULT_INBOUND_PARTITION = "aws"

    class InvalidRegionException(Exception):
        """An exception indicating that a region could not be matched to a partition."""

    arn_regex = re.compile(
        r"arn:"  # Prefix
        r"(?P<Partition>(aws|aws-cn|aws-iso|aws-iso-b|aws-us-gov)*):"  # Partition
        r"(?P<Service>[\w-]*):"  # Service (lambda, s3, ecs,...)
        r"(?P<Region>[\w-]*):"  # Region (us-east-1, us-gov-west-1,...)
        r"(?P<AccountID>[\w-]*):"  # AccountID
        r"(?P<ResourcePath>"  # Combine the resource type and id to the ResourcePath
        r"((?P<ResourceType>[\w-]*)[:/])?"  # ResourceType (optional, f.e. S3 bucket name)
        r"(?P<ResourceID>[\w\-/*]*)"  # Resource ID (f.e. file name in S3)
        r")"
    )

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        request = context.request
        # If this header is present, or the request is internal, remove it and continue the handler chain
        if request.headers.pop("LS-INTERNAL-REWRITE-HANDLER", None) or is_internal_call_context(
            request.headers
        ):
            return
        # since we are very early in the handler chain, we cannot use the request context here
        request_region = extract_region_from_headers(request.headers)
        forward_request = self.modify_request(request)
        # forward to the handler chain again
        result_response = forward(
            request=forward_request,
            forward_base_url=config.get_edge_url(),
            forward_path=forward_request.path,
            headers=forward_request.headers,
        )
        self.modify_response(result_response, request_region=request_region)
        response.update_from(result_response)

        # terminate this chain, as the request was proxied
        chain.terminate()

    def modify_request(self, request: Request) -> Request:
        """
        Modifies the request by rewriting ARNs

        :param request: Request
        :return: New request with rewritten data
        """
        # rewrite inbound request
        forward_rewritten_path, forward_rewritten_query_string = self._adjust_partition_in_path(
            request.full_path, self.DEFAULT_INBOUND_PARTITION
        )
        forward_rewritten_body = self._adjust_partition(
            restore_payload(request), self.DEFAULT_INBOUND_PARTITION
        )
        forward_rewritten_headers = self._adjust_partition(
            dict(request.headers), self.DEFAULT_INBOUND_PARTITION
        )

        # add header to signal request has already been rewritten
        forward_rewritten_headers["LS-INTERNAL-REWRITE-HANDLER"] = "1"
        # Create a new request with the updated data
        return Request(
            method=request.method,
            headers=forward_rewritten_headers,
            path=forward_rewritten_path,
            body=forward_rewritten_body,
            # we have to set query string to None to avoid it being counted as defined in werkzeug
            query_string=forward_rewritten_query_string,
        )

    def modify_response(self, response: Response, request_region: str):
        """
        Modifies the supplied response by rewriting the ARNs back based on the regions in the arn or the supplied region

        :param response: Response to be modified
        :param request_region: Region the original request was meant for
        """
        # rewrite response
        response.headers = self._adjust_partition(
            dict(response.headers), request_region=request_region
        )
        response.data = self._adjust_partition(response.data, request_region=request_region)
        self._post_process_response_headers(response)

    def _adjust_partition_in_path(self, path: str | bytes, static_partition: str = None):
        """Adjusts the (still url encoded) URL path"""
        parsed_url = urlparse(path)
        # Make sure to keep blank values, otherwise we drop query params which do not have a
        # value (f.e. "/?policy")
        decoded_query = parse_qs(qs=parsed_url.query, keep_blank_values=True)
        adjusted_path = self._adjust_partition(parsed_url.path, static_partition)
        adjusted_query = self._adjust_partition(decoded_query, static_partition)
        encoded_query = urlencode(adjusted_query, doseq=True)

        # Make sure to avoid empty equals signs (in between and in the end)
        encoded_query = encoded_query.replace("=&", "&")
        encoded_query = re.sub(r"=$", "", encoded_query)

        return adjusted_path, encoded_query or ""

    def _adjust_partition(self, source, static_partition: str = None, request_region: str = None):
        # Call this function recursively if we get a dictionary or a list
        if isinstance(source, dict):
            result = {}
            for k, v in source.items():
                result[k] = self._adjust_partition(v, static_partition, request_region)
            return result
        if isinstance(source, list):
            result = []
            for v in source:
                result.append(self._adjust_partition(v, static_partition, request_region))
            return result
        elif isinstance(source, bytes):
            try:
                decoded = unquote(to_str(source))
                adjusted = self._adjust_partition(decoded, static_partition, request_region)
                return to_bytes(adjusted)
            except UnicodeDecodeError:
                # If the body can't be decoded to a string, we return the initial source
                return source
        elif not isinstance(source, str):
            # Ignore any other types
            return source
        return self.arn_regex.sub(
            lambda m: self._adjust_match(m, static_partition, request_region), source
        )

    def _adjust_match(self, match: Match, static_partition: str = None, request_region: str = None):
        region = match.group("Region")
        partition = (
            self._partition_lookup(region, request_region)
            if static_partition is None
            else static_partition
        )
        service = match.group("Service")
        account_id = match.group("AccountID")
        resource_path = match.group("ResourcePath")
        return f"arn:{partition}:{service}:{region}:{account_id}:{resource_path}"

    def _partition_lookup(self, region: str, request_region: str = None):
        try:
            partition = self._get_partition_for_region(region)
        except ArnPartitionRewriteHandler.InvalidRegionException:
            try:
                partition = self._get_partition_for_region(request_region)
            except self.InvalidRegionException:
                try:
                    # If the region is not properly set (f.e. because it is set to a wildcard),
                    # the partition is determined based on the default region.
                    partition = self._get_partition_for_region(config.DEFAULT_REGION)
                except self.InvalidRegionException:
                    # If it also fails with the DEFAULT_REGION, we use us-east-1 as a fallback
                    partition = self._get_partition_for_region(AWS_REGION_US_EAST_1)
        return partition

    @staticmethod
    def _get_partition_for_region(region: Optional[str]) -> str:
        # Region-Partition matching is based on the "regionRegex" definitions in the endpoints.json
        # in the botocore package.
        if region and region.startswith("us-gov-"):
            return "aws-us-gov"
        elif region and region.startswith("us-iso-"):
            return "aws-iso"
        elif region and region.startswith("us-isob-"):
            return "aws-iso-b"
        elif region and region.startswith("cn-"):
            return "aws-cn"
        elif region and re.match(r"^(us|eu|ap|sa|ca|me|af)-\w+-\d+$", region):
            return "aws"
        else:
            raise ArnPartitionRewriteHandler.InvalidRegionException(
                f"Region ({region}) could not be matched to a partition."
            )

    @staticmethod
    def _post_process_response_headers(response: Response) -> None:
        """Adjust potential content lengths and checksums after modifying the response."""
        if response.headers and response.data:
            if "Content-Length" in response.headers:
                response.headers["Content-Length"] = str(len(to_bytes(response.data)))
            if "x-amz-crc32" in response.headers:
                response.headers["x-amz-crc32"] = calculate_crc32(response.data)
