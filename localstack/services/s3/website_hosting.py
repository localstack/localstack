import logging
import re
from functools import wraps
from typing import Callable, Dict, Optional, Union
from urllib.parse import urlparse

from moto.s3.exceptions import MissingBucket
from moto.s3.models import FakeBucket, FakeKey
from werkzeug.datastructures import Headers

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.s3 import (
    BucketName,
    NoSuchBucket,
    NoSuchKey,
    NoSuchWebsiteConfiguration,
    ObjectKey,
    RoutingRule,
    RoutingRules,
    WebsiteConfiguration,
)
from localstack.aws.protocol.serializer import gen_amzn_requestid
from localstack.constants import S3_STATIC_WEBSITE_HOSTNAME
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler
from localstack.services.s3.models import S3Store, get_moto_s3_backend, s3_stores
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

STATIC_WEBSITE_HOST_REGEX = f'<regex(".*"):bucket_name>.{S3_STATIC_WEBSITE_HOSTNAME}<port:port>'

_leading_whitespace_re = re.compile("(^[ \t]*)(?:[ \t\n])", re.MULTILINE)


class NoSuchKeyFromErrorDocument(NoSuchKey):
    code: str = "NoSuchKey"
    sender_fault: bool = False
    status_code: int = 404
    Key: Optional[ObjectKey]
    ErrorDocumentKey: Optional[ObjectKey]


def _get_bucket_from_moto(bucket: BucketName) -> FakeBucket:
    # TODO: check authorization for buckets as well? would need to be public-read at least
    # not enforced in the current provider
    try:
        return get_moto_s3_backend().get_bucket(bucket_name=bucket)
    except MissingBucket:
        ex = NoSuchBucket("The specified bucket does not exist")
        ex.BucketName = bucket
        raise ex


def _get_key_from_moto_bucket(moto_bucket: FakeBucket, key: ObjectKey) -> FakeKey:
    return moto_bucket.keys.get(key)


def _get_store() -> S3Store:
    return s3_stores[get_aws_account_id()][aws_stack.get_region()]


def _get_bucket_website_configuration(bucket: BucketName) -> WebsiteConfiguration:
    """
    Retrieve the website configuration for the given bucket
    :param bucket: the bucket name
    :raises NoSuchWebsiteConfiguration if the bucket does not have a website config
    :return: the WebsiteConfiguration of the bucket
    """
    website_configuration = _get_store().bucket_website_configuration.get(bucket)
    if not website_configuration:
        ex = NoSuchWebsiteConfiguration(
            "The specified bucket does not have a website configuration"
        )
        ex.BucketName = bucket
        raise ex
    return website_configuration


def _website_handler(
    request: Request, bucket_name: str, path: str = None, port: str = None
) -> Response:
    """
    Tries to serve the key, and if an Exception is encountered, returns a generic response
    This will allow to easily extend it to 403 exceptions
    :param request: router Request object
    :param bucket_name: str, bucket name
    :param path: the path of the request
    :param port: /
    :return: Response object
    """
    if request.method != "GET":
        return Response(
            _create_405_error_string(request.method, request_id=gen_amzn_requestid()), status=405
        )

    try:
        return _serve_key(request, bucket_name, path)

    except (NoSuchBucket, NoSuchWebsiteConfiguration, NoSuchKeyFromErrorDocument, NoSuchKey) as e:
        resource_name = e.Key if hasattr(e, "Key") else e.BucketName
        response_body = _create_404_error_string(
            code=e.code,
            message=e.message,
            resource_name=resource_name,
            request_id=gen_amzn_requestid(),
            from_error_document=getattr(e, "ErrorDocumentKey", None),
        )
        return Response(response_body, status=e.status_code)

    except Exception:
        LOG.exception("Exception encountered while trying to serve s3-website at %s", request.url)
        return Response(_create_500_error_string(), status=500)


def _serve_key(request: Request, bucket_name: BucketName, path: str = None) -> Response:
    """
    Serves the S3 key as a website handler. It will match routing rules set in the configuration first, and redirect
    the request if necessary. They are specific case for handling configured index, see the docs:
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/IndexDocumentSupport.html
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/how-to-page-redirect.html
    :param request: Request object received by the router
    :param bucket_name: bucket name contained in the host name
    :param path: path of the request, corresponds to the S3 key
    :return: Response object, either the key, a redirection or an error
    """
    bucket = _get_bucket_from_moto(bucket=bucket_name)
    headers = {}

    website_config = _get_bucket_website_configuration(bucket_name)

    redirection = website_config.get("RedirectAllRequestsTo")
    if redirection:
        parsed_url = urlparse(request.url)
        redirect_to = request.url.replace(parsed_url.netloc, redirection["HostName"])
        if protocol := redirection.get("Protocol"):
            redirect_to = redirect_to.replace(parsed_url.scheme, protocol)

        headers["Location"] = redirect_to
        return Response("", status=301, headers=headers)

    key_name = path
    routing_rules = website_config.get("RoutingRules")
    # checks for prefix rules, before trying to get the key
    if (
        key_name
        and routing_rules
        and (rule := _find_matching_rule(routing_rules, key_name=key_name))
    ):
        redirect_response = _get_redirect_from_routing_rule(request, rule)
        return redirect_response

    # if the URL ends with a trailing slash, try getting the index first
    is_folder = request.url[-1] == "/"
    if (
        not key_name or is_folder
    ):  # the path automatically remove the trailing slash, even with strict_slashes=False
        index_key = website_config["IndexDocument"]["Suffix"]
        key_name = f"{key_name}{index_key}" if key_name else index_key

    key = _get_key_from_moto_bucket(bucket, key_name)
    if not key:
        if not is_folder:
            # try appending the index suffix in case we're accessing a "folder" without a trailing slash
            index_key = website_config["IndexDocument"]["Suffix"]
            key = _get_key_from_moto_bucket(bucket, f"{key_name}/{index_key}")
            if key:
                return Response("", status=302, headers={"Location": f"/{key_name}/"})

        # checks for error code (and prefix) rules, after trying to get the key
        if routing_rules and (
            rule := _find_matching_rule(routing_rules, key_name=key_name, error_code=404)
        ):
            redirect_response = _get_redirect_from_routing_rule(request, rule)
            return redirect_response

        # tries to get the error document, otherwise raises NoSuchKey
        response = _get_error_document(
            website_config=website_config,
            bucket=bucket,
            missing_key=key_name,
        )
        return response

    if key.website_redirect_location:
        headers["Location"] = key.website_redirect_location
        return Response("", status=301, headers=headers)

    if _check_if_headers(request.headers, key=key):
        return Response("", status=304)

    headers = _get_response_headers_from_key(key)
    return Response(key.value, headers=headers)


def _get_response_headers_from_key(key: FakeKey) -> Dict[str, str]:
    """
    Get some header values from the key
    :param key: the key name
    :return: headers from the key to be part of the response
    """
    response_headers = {}
    if content_type := key.metadata.get("Content-Type"):
        response_headers["Content-Type"] = content_type
    if key.etag:
        response_headers["etag"] = key.etag

    return response_headers


def _find_matching_rule(
    routing_rules: RoutingRules, key_name: ObjectKey, error_code: int = None
) -> Union[RoutingRule, None]:
    """
    Iterate over the routing rules set in the configuration, and return the first that match the key name and/or the
    error code (in the 4XX range).
    :param routing_rules: RoutingRules part of WebsiteConfiguration
    :param key_name:
    :param error_code: error code of the Response in the 4XX range
    :return: a RoutingRule if matched, or None
    """
    # TODO: we could separate rules depending in they have the HttpErrorCodeReturnedEquals field
    #  we would not try to match on them early, no need to iterate on them
    #  and iterate them over only if an exception is encountered
    for rule in routing_rules:
        if condition := rule.get("Condition"):
            prefix = condition.get("KeyPrefixEquals")
            return_http_code = condition.get("HttpErrorCodeReturnedEquals")
            # if both prefix matching and http error matching conditions are set
            if prefix and return_http_code:
                if key_name.startswith(prefix) and error_code == int(return_http_code):
                    return rule
                else:
                    # it must either match both or it does not apply
                    continue
            # only prefix is set, but this should have been matched before the error
            elif prefix and key_name.startswith(prefix):
                return rule
            elif return_http_code and error_code == int(return_http_code):
                return rule

        else:
            # if no Condition is set, the redirect is applied to all requests
            return rule


def _get_redirect_from_routing_rule(request: Request, routing_rule: RoutingRule) -> Response:
    """
    Return a redirect Response object created with the different parameters set in the RoutingRule
    :param request: the original Request object received from the router
    :param routing_rule: a RoutingRule from the WebsiteConfiguration
    :return: a redirect Response
    """
    parsed_url = urlparse(request.url)
    redirect_to = request.url
    redirect = routing_rule["Redirect"]
    if host_name := redirect.get("HostName"):
        redirect_to = redirect_to.replace(parsed_url.netloc, host_name)
    if protocol := redirect.get("Protocol"):
        redirect_to = redirect_to.replace(parsed_url.scheme, protocol)
    if redirect_to_key := redirect.get("ReplaceKeyWith"):
        redirect_to = redirect_to.replace(parsed_url.path, f"/{redirect_to_key}")
    elif "ReplaceKeyPrefixWith" in redirect:  # the value might be empty and it's a valid config
        matched_prefix = routing_rule["Condition"].get("KeyPrefixEquals", "")
        redirect_to = redirect_to.replace(matched_prefix, redirect.get("ReplaceKeyPrefixWith"), 1)

    return Response(
        "", headers={"Location": redirect_to}, status=redirect.get("HttpRedirectCode", 301)
    )


def _get_error_document(
    website_config: WebsiteConfiguration, bucket: FakeBucket, missing_key: ObjectKey
) -> Response:
    """
    Either tries to get the
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html
    :param website_config: the bucket WebsiteConfiguration
    :param bucket: the bucket object from moto
    :param missing_key: the missing key not found in the bucket
    :return:
    """
    headers = {}
    if error_document := website_config.get("ErrorDocument"):
        # if an error document is configured, try to fetch the key
        error_key = error_document["Key"]
        key = _get_key_from_moto_bucket(bucket, error_key)
        if key:
            # if the key is found, return the key, or if that key has a redirect, return a redirect
            error_body = key.value
            if key.website_redirect_location:
                headers["Location"] = key.website_redirect_location
                return Response("", status=301, headers=headers)

            headers = _get_response_headers_from_key(key)
            return Response(error_body, status=404, headers=headers)
        else:
            ex = NoSuchKeyFromErrorDocument("The specified key does not exist.")
            ex.Key = missing_key
            ex.ErrorDocumentKey = error_key
            raise ex

    else:
        ex = NoSuchKey("The specified key does not exist.")
        ex.Key = missing_key
        raise ex


def _check_if_headers(headers: Headers, key: FakeKey) -> bool:
    # TODO: add other conditions here If-Modified-Since, etc etc
    if "if-none-match" in headers and key.etag and key.etag in headers["if-none-match"]:
        return True


def register_website_hosting_routes(router: Router[Handler]):
    """
    Registers the S3 website hosting handlers into the given router.

    :param router: the router to add the handlers into.
    """
    router.add(
        path="/",
        host=STATIC_WEBSITE_HOST_REGEX,
        endpoint=_website_handler,
    )
    router.add(
        path="/<path:path>",
        host=STATIC_WEBSITE_HOST_REGEX,
        endpoint=_website_handler,
    )


def _remove_leading_whitespace(response: str) -> str:
    return re.sub(_leading_whitespace_re, "", response)


def _flatten_html_response(fn: Callable[[...], str]):
    @wraps(fn)
    def wrapper(*args, **kwargs) -> str:
        r = fn(*args, **kwargs)
        return _remove_leading_whitespace(r)

    return wrapper


@_flatten_html_response
def _create_404_error_string(
    code: str, message: str, resource_name: str, request_id: str, from_error_document: str = None
) -> str:
    # TODO: the nested error could be permission related
    #  permission are not enforced currently
    resource_key = "Key" if "Key" in code else "BucketName"
    return f"""<html>
    <head><title>404 Not Found</title></head>
    <body>
        <h1>404 Not Found</h1>
        <ul>
            <li>Code: {code}</li>
            <li>Message: {message}</li>
            <li>{resource_key}: {resource_name}</li>
            <li>RequestId: {request_id}</li>
            <li>HostId: h6t23Wl2Ndijztq+COn9kvx32omFVRLLtwk36D6+2/CIYSey+Uox6kBxRgcnAASsgnGwctU6zzU=</li>
        </ul>
        {_create_nested_404_error_string(from_error_document)}
        <hr/>
    </body>
</html>
"""


def _create_nested_404_error_string(error_document_key: str) -> str:
    if not error_document_key:
        return ""
    return f"""<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>
        <ul>
            <li>Code: NoSuchKey</li>
            <li>Message: The specified key does not exist.</li>
            <li>Key: {error_document_key}</li>
        </ul>
    """


@_flatten_html_response
def _create_405_error_string(method: str, request_id: str) -> str:
    return f"""<html>
    <head><title>405 Method Not Allowed</title></head>
    <body>
        <h1>405 Method Not Allowed</h1>
        <ul>
            <li>Code: MethodNotAllowed</li>
            <li>Message: The specified method is not allowed against this resource.</li>
            <li>Method: {method.upper()}</li>
            <li>ResourceType: OBJECT</li>
            <li>RequestId: {request_id}</li>
            <li>HostId: h6t23Wl2Ndijztq+COn9kvx32omFVRLLtwk36D6+2/CIYSey+Uox6kBxRgcnAASsgnGwctU6zzU=</li>
        </ul>
        <hr/>
    </body>
</html>
"""


@_flatten_html_response
def _create_500_error_string() -> str:
    return """<html>
        <head><title>500 Service Error</title></head>
        <body>
            <h1>500 Service Error</h1>
            <hr/>
        </body>
    </html>
    """
