import logging
import re
from functools import wraps
from typing import Callable, Dict, Optional, Union
from urllib.parse import urlparse

from werkzeug.datastructures import Headers

from localstack.aws.api.s3 import (
    BucketName,
    ErrorDocument,
    GetObjectOutput,
    NoSuchKey,
    NoSuchWebsiteConfiguration,
    ObjectKey,
    RoutingRule,
    RoutingRules,
)
from localstack.aws.connect import connect_to
from localstack.aws.protocol.serializer import gen_amzn_requestid
from localstack.http import Request, Response, Router
from localstack.http.dispatcher import Handler

LOG = logging.getLogger(__name__)

STATIC_WEBSITE_HOST_REGEX = '<regex(".*"):bucket_name>.s3-website.<regex(".*"):domain>'

_leading_whitespace_re = re.compile("(^[ \t]*)(?:[ \t\n])", re.MULTILINE)


class NoSuchKeyFromErrorDocument(NoSuchKey):
    code: str = "NoSuchKey"
    sender_fault: bool = False
    status_code: int = 404
    Key: Optional[ObjectKey]
    ErrorDocumentKey: Optional[ObjectKey]


class S3WebsiteHostingHandler:
    def __init__(self):
        # TODO: once we implement ACLs, maybe revisit the way we use the client/verify the bucket/object's ACL
        self.s3_client = connect_to().s3

    def __call__(
        self,
        request: Request,
        bucket_name: str,
        domain: str = None,
        path: str = None,
    ) -> Response:
        """
        Tries to serve the key, and if an Exception is encountered, returns a generic response
        This will allow to easily extend it to 403 exceptions
        :param request: router Request object
        :param bucket_name: str, bucket name
        :param domain: str, domain name
        :param path: the path of the request
        :return: Response object
        """
        if request.method != "GET":
            return Response(
                _create_405_error_string(request.method, request_id=gen_amzn_requestid()),
                status=405,
            )

        try:
            return self._serve_object(request, bucket_name, path)

        except (NoSuchKeyFromErrorDocument, NoSuchWebsiteConfiguration) as e:
            resource_name = e.Key if hasattr(e, "Key") else e.BucketName
            response_body = _create_404_error_string(
                code=e.code,
                message=e.message,
                resource_name=resource_name,
                request_id=gen_amzn_requestid(),
                from_error_document=getattr(e, "ErrorDocumentKey", None),
            )
            return Response(response_body, status=e.status_code)

        except self.s3_client.exceptions.ClientError as e:
            error = e.response["Error"]
            if error["Code"] not in ("NoSuchKey", "NoSuchBucket", "NoSuchWebsiteConfiguration"):
                raise

            resource_name = error.get("Key", error.get("BucketName"))
            response_body = _create_404_error_string(
                code=error["Code"],
                message=error["Message"],
                resource_name=resource_name,
                request_id=gen_amzn_requestid(),
                from_error_document=getattr(e, "ErrorDocumentKey", None),
            )
            return Response(response_body, status=e.response["ResponseMetadata"]["HTTPStatusCode"])

        except Exception:
            LOG.exception(
                "Exception encountered while trying to serve s3-website at %s", request.url
            )
            return Response(_create_500_error_string(), status=500)

    def _serve_object(
        self, request: Request, bucket_name: BucketName, path: str = None
    ) -> Response:
        """
        Serves the S3 Object as a website handler. It will match routing rules set in the configuration first,
        and redirect the request if necessary. They are specific case for handling configured index, see the docs:
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/IndexDocumentSupport.html
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/how-to-page-redirect.html
        :param request: Request object received by the router
        :param bucket_name: bucket name contained in the host name
        :param path: path of the request, corresponds to the S3 Object key
        :return: Response object, either the Object, a redirection or an error
        """

        website_config = self.s3_client.get_bucket_website(Bucket=bucket_name)
        headers = {}

        redirection = website_config.get("RedirectAllRequestsTo")
        if redirection:
            parsed_url = urlparse(request.url)
            redirect_to = request.url.replace(parsed_url.netloc, redirection["HostName"])
            if protocol := redirection.get("Protocol"):
                redirect_to = redirect_to.replace(parsed_url.scheme, protocol)

            headers["Location"] = redirect_to
            return Response("", status=301, headers=headers)

        object_key = path
        routing_rules = website_config.get("RoutingRules")
        # checks for prefix rules, before trying to get the key
        if (
            object_key
            and routing_rules
            and (rule := self._find_matching_rule(routing_rules, object_key=object_key))
        ):
            redirect_response = self._get_redirect_from_routing_rule(request, rule)
            return redirect_response

        # if the URL ends with a trailing slash, try getting the index first
        is_folder = request.url[-1] == "/"
        if (
            not object_key or is_folder
        ):  # the path automatically remove the trailing slash, even with strict_slashes=False
            index_key = website_config["IndexDocument"]["Suffix"]
            object_key = f"{object_key}{index_key}" if object_key else index_key

        try:
            s3_object = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
        except self.s3_client.exceptions.NoSuchKey:
            if not is_folder:
                # try appending the index suffix in case we're accessing a "folder" without a trailing slash
                index_key = website_config["IndexDocument"]["Suffix"]
                try:
                    self.s3_client.head_object(Bucket=bucket_name, Key=f"{object_key}/{index_key}")
                    return Response("", status=302, headers={"Location": f"/{object_key}/"})
                except self.s3_client.exceptions.ClientError:
                    pass

            # checks for error code (and prefix) rules, after trying to get the key
            if routing_rules and (
                rule := self._find_matching_rule(
                    routing_rules, object_key=object_key, error_code=404
                )
            ):
                redirect_response = self._get_redirect_from_routing_rule(request, rule)
                return redirect_response

            # tries to get the error document, otherwise raises NoSuchKey
            if error_document := website_config.get("ErrorDocument"):
                return self._return_error_document(
                    error_document=error_document,
                    bucket=bucket_name,
                    missing_key=object_key,
                )
            else:
                # If not ErrorDocument is configured, raise NoSuchKey
                raise

        if website_redirect_location := s3_object.get("WebsiteRedirectLocation"):
            headers["Location"] = website_redirect_location
            return Response("", status=301, headers=headers)

        if self._check_if_headers(request.headers, s3_object=s3_object):
            return Response("", status=304)

        headers = self._get_response_headers_from_object(s3_object)
        return Response(s3_object["Body"], headers=headers)

    def _return_error_document(
        self,
        error_document: ErrorDocument,
        bucket: BucketName,
        missing_key: ObjectKey,
    ) -> Response:
        """
        Try to retrieve the configured ErrorDocument and return the response with its body
        https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html
        :param error_document: the ErrorDocument from the bucket WebsiteConfiguration
        :param bucket: the bucket name
        :param missing_key: the missing key not found in the bucket
        :return: a Response, either a redirection or containing the Body of the ErrorDocument
        :raises NoSuchKeyFromErrorDocument if the ErrorDocument is not found
        """
        headers = {}
        error_key = error_document["Key"]
        try:
            s3_object = self.s3_client.get_object(Bucket=bucket, Key=error_key)
            # if the key is found, return the key, or if that key has a redirect, return a redirect

            if website_redirect_location := s3_object.get("WebsiteRedirectLocation"):
                headers["Location"] = website_redirect_location
                return Response("", status=301, headers=headers)

            headers = self._get_response_headers_from_object(s3_object)
            return Response(s3_object["Body"], status=404, headers=headers)

        except self.s3_client.exceptions.NoSuchKey:
            raise NoSuchKeyFromErrorDocument(
                "The specified key does not exist.",
                Key=missing_key,
                ErrorDocumentKey=error_key,
            )

    @staticmethod
    def _get_response_headers_from_object(get_object_response: GetObjectOutput) -> Dict[str, str]:
        """
        Only return some headers from the S3 Object
        :param get_object_response: the response from S3.GetObject
        :return: headers from the object to be part of the response
        """
        response_headers = {}
        if content_type := get_object_response.get("ContentType"):
            response_headers["Content-Type"] = content_type
        if etag := get_object_response.get("ETag"):
            response_headers["etag"] = etag

        return response_headers

    @staticmethod
    def _check_if_headers(headers: Headers, s3_object: GetObjectOutput) -> bool:
        # TODO: add other conditions here If-Modified-Since, etc etc
        etag = s3_object.get("ETag")
        # last_modified = s3_object.get("LastModified")  # TODO
        if "if-none-match" in headers and etag and etag in headers["if-none-match"]:
            return True

    @staticmethod
    def _find_matching_rule(
        routing_rules: RoutingRules, object_key: ObjectKey, error_code: int = None
    ) -> Union[RoutingRule, None]:
        """
        Iterate over the routing rules set in the configuration, and return the first that match the key name and/or the
        error code (in the 4XX range).
        :param routing_rules: RoutingRules part of WebsiteConfiguration
        :param object_key: ObjectKey
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
                    if object_key.startswith(prefix) and error_code == int(return_http_code):
                        return rule
                    else:
                        # it must either match both or it does not apply
                        continue
                # only prefix is set, but this should have been matched before the error
                elif prefix and object_key.startswith(prefix):
                    return rule
                elif return_http_code and error_code == int(return_http_code):
                    return rule

            else:
                # if no Condition is set, the redirect is applied to all requests
                return rule

    @staticmethod
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
            redirect_to = redirect_to.replace(
                matched_prefix, redirect.get("ReplaceKeyPrefixWith"), 1
            )

        return Response(
            "", headers={"Location": redirect_to}, status=redirect.get("HttpRedirectCode", 301)
        )


def register_website_hosting_routes(
    router: Router[Handler], handler: S3WebsiteHostingHandler = None
):
    """
    Registers the S3 website hosting handler into the given router.
    :param handler: an S3WebsiteHosting handler
    :param router: the router to add the handlers into.
    """
    handler = handler or S3WebsiteHostingHandler()
    router.add(
        path="/",
        host=STATIC_WEBSITE_HOST_REGEX,
        endpoint=handler,
    )
    router.add(
        path="/<path:path>",
        host=STATIC_WEBSITE_HOST_REGEX,
        endpoint=handler,
    )


def _flatten_html_response(fn: Callable[[...], str]):
    @wraps(fn)
    def wrapper(*args, **kwargs) -> str:
        r = fn(*args, **kwargs)
        # remove leading whitespace
        return re.sub(_leading_whitespace_re, "", r)

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
