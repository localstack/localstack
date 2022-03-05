import logging
import os
import re
from abc import ABC
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

import botocore
import xmltodict
from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.exceptions import S3ClientError
from moto.s3.responses import S3_ALL_MULTIPARTS, MalformedXML, is_delete_keys, minidom
from moto.s3.utils import undo_clean_key_name
from moto.s3bucket_path import utils as s3bucket_path_utils

from localstack import config, constants
from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    MFA,
    AbortMultipartUploadOutput,
    AccelerateConfiguration,
    AcceptRanges,
    AccessControlPolicy,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    Body,
    BucketCannedACL,
    BucketKeyEnabled,
    BucketLifecycleConfiguration,
    BucketLoggingStatus,
    BucketName,
    BypassGovernanceRetention,
    CacheControl,
    CompletedMultipartUpload,
    CompleteMultipartUploadOutput,
    ConfirmRemoveSelfBucketAccess,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentMD5,
    ContentRange,
    ContentType,
    CopyObjectOutput,
    CopySource,
    CopySourceIfMatch,
    CopySourceIfModifiedSince,
    CopySourceIfNoneMatch,
    CopySourceIfUnmodifiedSince,
    CopySourceRange,
    CopySourceSSECustomerAlgorithm,
    CopySourceSSECustomerKey,
    CopySourceSSECustomerKeyMD5,
    CORSConfiguration,
    CreateBucketConfiguration,
    CreateBucketOutput,
    CreateMultipartUploadOutput,
    Delete,
    DeleteMarker,
    DeleteObjectOutput,
    DeleteObjectsOutput,
    DeleteObjectTaggingOutput,
    Delimiter,
    EncodingType,
    ErrorCode,
    ErrorMessage,
    ETag,
    Expiration,
    Expires,
    Expression,
    ExpressionType,
    FetchOwner,
    GetBucketAccelerateConfigurationOutput,
    GetBucketAclOutput,
    GetBucketAnalyticsConfigurationOutput,
    GetBucketCorsOutput,
    GetBucketEncryptionOutput,
    GetBucketIntelligentTieringConfigurationOutput,
    GetBucketInventoryConfigurationOutput,
    GetBucketLifecycleConfigurationOutput,
    GetBucketLifecycleOutput,
    GetBucketLocationOutput,
    GetBucketLoggingOutput,
    GetBucketMetricsConfigurationOutput,
    GetBucketOwnershipControlsOutput,
    GetBucketPolicyOutput,
    GetBucketPolicyStatusOutput,
    GetBucketReplicationOutput,
    GetBucketRequestPaymentOutput,
    GetBucketTaggingOutput,
    GetBucketVersioningOutput,
    GetBucketWebsiteOutput,
    GetObjectAclOutput,
    GetObjectLegalHoldOutput,
    GetObjectLockConfigurationOutput,
    GetObjectOutput,
    GetObjectResponseStatusCode,
    GetObjectRetentionOutput,
    GetObjectTaggingOutput,
    GetObjectTorrentOutput,
    GetPublicAccessBlockOutput,
    GrantFullControl,
    GrantRead,
    GrantReadACP,
    GrantWrite,
    GrantWriteACP,
    HeadObjectOutput,
    IfMatch,
    IfModifiedSince,
    IfNoneMatch,
    IfUnmodifiedSince,
    InputSerialization,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InventoryConfiguration,
    InventoryId,
    KeyMarker,
    LastModified,
    LifecycleConfiguration,
    ListBucketAnalyticsConfigurationsOutput,
    ListBucketIntelligentTieringConfigurationsOutput,
    ListBucketInventoryConfigurationsOutput,
    ListBucketMetricsConfigurationsOutput,
    ListBucketsOutput,
    ListMultipartUploadsOutput,
    ListObjectsOutput,
    ListObjectsV2Output,
    ListObjectVersionsOutput,
    ListPartsOutput,
    Marker,
    MaxKeys,
    MaxParts,
    MaxUploads,
    Metadata,
    MetadataDirective,
    MetricsConfiguration,
    MetricsId,
    MissingMeta,
    MultipartUploadId,
    NoSuchBucket,
    NotificationConfiguration,
    NotificationConfigurationDeprecated,
    ObjectCannedACL,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockEnabledForBucket,
    ObjectLockLegalHold,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectLockRetainUntilDate,
    ObjectLockRetention,
    ObjectLockToken,
    ObjectOwnership,
    ObjectVersionId,
    OutputSerialization,
    OwnershipControls,
    PartNumber,
    PartNumberMarker,
    PartsCount,
    Policy,
    Prefix,
    PublicAccessBlockConfiguration,
    PutObjectAclOutput,
    PutObjectLegalHoldOutput,
    PutObjectLockConfigurationOutput,
    PutObjectOutput,
    PutObjectRetentionOutput,
    PutObjectTaggingOutput,
    Range,
    ReplicationConfiguration,
    ReplicationStatus,
    RequestCharged,
    RequestPayer,
    RequestPaymentConfiguration,
    RequestProgress,
    RequestRoute,
    RequestToken,
    ResponseCacheControl,
    ResponseContentDisposition,
    ResponseContentEncoding,
    ResponseContentLanguage,
    ResponseContentType,
    ResponseExpires,
    Restore,
    RestoreObjectOutput,
    RestoreRequest,
    S3Api,
    ScanRange,
    SelectObjectContentOutput,
    ServerSideEncryption,
    ServerSideEncryptionConfiguration,
    SkipValidation,
    SSECustomerAlgorithm,
    SSECustomerKey,
    SSECustomerKeyMD5,
    SSEKMSEncryptionContext,
    SSEKMSKeyId,
    StartAfter,
    StorageClass,
    TagCount,
    Tagging,
    TaggingDirective,
    TaggingHeader,
    Token,
    UploadIdMarker,
    UploadPartCopyOutput,
    UploadPartOutput,
    VersionIdMarker,
    VersioningConfiguration,
    WebsiteConfiguration,
    WebsiteRedirectLocation,
)
from localstack.aws.proxy import AwsApiListener
from localstack.constants import AWS_REGION_US_EAST_1, BINARY_OCTET_STREAM, HEADER_CONTENT_TYPE
from localstack.http import Response
from localstack.services.awslambda.lambda_utils import ClientError
from localstack.services.messages import Headers, MessagePayload
from localstack.services.moto import MotoFallbackDispatcher, call_moto, call_moto_with_request
from localstack.services.s3 import multipart_content, s3_listener, s3_utils
from localstack.services.s3.s3_listener import (
    NOTIFICATION_DESTINATION_TYPES,
    OBJECT_METADATA_KEY_PREFIX,
    POLICY_EXPIRATION_FORMAT1,
    POLICY_EXPIRATION_FORMAT2,
    S3_NOTIFICATIONS,
    ProxyListenerS3,
    add_accept_range_header,
    add_response_metadata_headers,
    append_aws_request_troubleshooting_headers,
    append_cors_headers,
    append_last_modified_headers,
    append_list_objects_marker,
    convert_to_chunked_encoding,
    event_type_matches,
    expand_redirect_url,
    filter_rules_match,
    fix_creation_date,
    fix_delete_objects_response,
    fix_delimiter,
    fix_location_constraint,
    fix_metadata_key_underscores,
    fix_range_content_type,
    get_event_message,
    is_bucket_available,
    is_object_expired,
    is_object_specific_request,
    no_such_bucket,
    no_such_key_error,
    ret304_on_etag,
    send_notification_for_subscriber,
    send_notifications,
    set_object_expiry,
)
from localstack.services.s3.s3_utils import (
    ALLOWED_HEADER_OVERRIDES,
    extract_bucket_name,
    is_static_website,
    normalize_bucket_name,
    uses_host_addressing,
)
from localstack.utils import json
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import (
    create_sqs_system_attributes,
    is_invalid_html_response,
    requests_response,
)
from localstack.utils.common import get_service_protocol
from localstack.utils.generic.dict_utils import get_safe
from localstack.utils.patch import patch
from localstack.utils.strings import short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)

# max file size for S3 objects kept in memory (500 KB by default)
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

# see https://stackoverflow.com/questions/50480924/regex-for-s3-bucket-name#50484916
BUCKET_NAME_REGEX = (
    r"(?=^.{3,63}$)(?!^(\d+\.)+\d+$)"
    + r"(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)"
)

# temporary state
TMP_STATE = {}
TMP_TAG = {}


# TODO: remove! just for debugging during migration.
class S3ApiListener(AwsApiListener):
    def __init__(self):
        super().__init__("s3", MotoFallbackDispatcher(S3Provider()))

    @staticmethod
    def get_201_response(key, bucket_name):
        return """
                <PostResponse>
                    <Location>{protocol}://{host}/{encoded_key}</Location>
                    <Bucket>{bucket}</Bucket>
                    <Key>{key}</Key>
                    <ETag>{etag}</ETag>
                </PostResponse>
                """.format(
            protocol=get_service_protocol(),
            host=config.HOSTNAME_EXTERNAL,
            encoded_key=quote(key, safe=""),
            key=key,
            bucket=bucket_name,
            etag="d41d8cd98f00b204e9800998ecf8427f",
        )

    @staticmethod
    def is_s3_copy_request(headers, path):
        return "x-amz-copy-source" in headers or "x-amz-copy-source" in path

    @staticmethod
    def is_create_multipart_request(query):
        return query.startswith("uploads")

    @staticmethod
    def is_multipart_upload(query):
        return query.startswith("uploadId")

    @staticmethod
    def _update_location(content, bucket_name):
        bucket_name = normalize_bucket_name(bucket_name)

        host = config.HOSTNAME_EXTERNAL
        if ":" not in host:
            host = f"{host}:{config.service_port('s3')}"
        return re.sub(
            r"<Location>\s*([a-zA-Z0-9\-]+)://[^/]+/([^<]+)\s*</Location>",
            r"<Location>%s://%s/%s/\2</Location>" % (get_service_protocol(), host, bucket_name),
            content,
            flags=re.MULTILINE,
        )

    @staticmethod
    def is_query_allowable(method, query):
        # Generally if there is a query (some/path/with?query) we don't want to send notifications
        if not query:
            return True
        # Except we do want to notify on multipart and presigned url upload completion
        contains_cred = "X-Amz-Credential" in query and "X-Amz-Signature" in query
        contains_key = "AWSAccessKeyId" in query and "Signature" in query
        # nodejs sdk putObjectCommand is adding x-id=putobject in the query
        allowed_query = "x-id=" in query.lower()
        if (
            (method == "POST" and query.startswith("uploadId"))
            or contains_cred
            or contains_key
            or allowed_query
        ):
            return True

    @staticmethod
    def parse_policy_expiration_date(expiration_string):
        try:
            dt = datetime.datetime.strptime(expiration_string, POLICY_EXPIRATION_FORMAT1)
        except Exception:
            dt = datetime.datetime.strptime(expiration_string, POLICY_EXPIRATION_FORMAT2)

        # both date formats assume a UTC timezone ('Z' suffix), but it's not parsed as tzinfo into the datetime object
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    @staticmethod
    def error_response(message, code, status_code=400):
        result = {"Error": {"Code": code, "Message": message}}
        content = xmltodict.unparse(result)
        return S3ApiListener.xml_response(content, status_code=status_code)

    @staticmethod
    def xml_response(content, status_code=200):
        headers = {"Content-Type": "application/xml"}
        return requests_response(content, status_code=status_code, headers=headers)

    @staticmethod
    def send_notifications(method, bucket_name, object_path, version_id, headers):
        for bucket, notifs in S3_NOTIFICATIONS.items():
            if normalize_bucket_name(bucket) == normalize_bucket_name(bucket_name):
                action = {
                    "PUT": "ObjectCreated",
                    "POST": "ObjectCreated",
                    "DELETE": "ObjectRemoved",
                }[method]
                # TODO: support more detailed methods, e.g., DeleteMarkerCreated
                # http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
                if action == "ObjectCreated" and method == "PUT" and "x-amz-copy-source" in headers:
                    api_method = "Copy"
                elif (
                    action == "ObjectCreated"
                    and method == "POST"
                    and "form-data" in headers.get("Content-Type", "")
                ):
                    api_method = "Post"
                elif action == "ObjectCreated" and method == "POST":
                    api_method = "CompleteMultipartUpload"
                else:
                    api_method = {"PUT": "Put", "POST": "Post", "DELETE": "Delete"}[method]

                event_name = "%s:%s" % (action, api_method)
                for notif in notifs:
                    send_notification_for_subscriber(
                        notif,
                        bucket_name,
                        object_path,
                        version_id,
                        api_method,
                        action,
                        event_name,
                        headers,
                    )

    @staticmethod
    def send_notification_for_subscriber(
        notif, bucket_name, object_path, version_id, api_method, action, event_name, headers
    ):
        bucket_name = normalize_bucket_name(bucket_name)

        if not event_type_matches(notif["Event"], action, api_method) or not filter_rules_match(
            notif.get("Filter"), object_path
        ):
            return

        key = unquote(object_path.replace("//", "/"))[1:]

        s3_client = aws_stack.connect_to_service("s3")
        object_data = {}
        try:
            object_data = s3_client.head_object(Bucket=bucket_name, Key=key)
        except botocore.exceptions.ClientError:
            pass

        # build event message
        message = get_event_message(
            event_name=event_name,
            bucket_name=bucket_name,
            file_name=key,
            etag=object_data.get("ETag", ""),
            file_size=object_data.get("ContentLength", 0),
            version_id=version_id,
        )
        message = json.dumps(message)

        if notif.get("Queue"):
            region = aws_stack.extract_region_from_arn(notif["Queue"])
            sqs_client = aws_stack.connect_to_service("sqs", region_name=region)
            try:
                queue_url = aws_stack.sqs_queue_url_for_arn(notif["Queue"])
                sqs_client.send_message(
                    QueueUrl=queue_url,
                    MessageBody=message,
                    MessageSystemAttributes=create_sqs_system_attributes(headers),
                )
            except Exception as e:
                LOG.warning(
                    'Unable to send notification for S3 bucket "%s" to SQS queue "%s": %s',
                    bucket_name,
                    notif["Queue"],
                    e,
                )
        if notif.get("Topic"):
            region = aws_stack.extract_region_from_arn(notif["Topic"])
            sns_client = aws_stack.connect_to_service("sns", region_name=region)
            try:
                sns_client.publish(
                    TopicArn=notif["Topic"],
                    Message=message,
                    Subject="Amazon S3 Notification",
                )
            except Exception as e:
                LOG.warning(
                    'Unable to send notification for S3 bucket "%s" to SNS topic "%s": %s',
                    bucket_name,
                    notif["Topic"],
                    e,
                )
        # CloudFunction and LambdaFunction are semantically identical
        lambda_function_config = notif.get("CloudFunction") or notif.get("LambdaFunction")
        if lambda_function_config:
            # make sure we don't run into a socket timeout
            region = aws_stack.extract_region_from_arn(lambda_function_config)
            connection_config = botocore.config.Config(read_timeout=300)
            lambda_client = aws_stack.connect_to_service(
                "lambda", config=connection_config, region_name=region
            )
            try:
                lambda_client.invoke(
                    FunctionName=lambda_function_config,
                    InvocationType="Event",
                    Payload=message,
                )
            except Exception:
                LOG.warning(
                    'Unable to send notification for S3 bucket "%s" to Lambda function "%s".',
                    bucket_name,
                    lambda_function_config,
                )

        if not filter(lambda x: notif.get(x), NOTIFICATION_DESTINATION_TYPES):
            LOG.warning(
                "Neither of %s defined for S3 notification.",
                "/".join(NOTIFICATION_DESTINATION_TYPES),
            )

    def return_response(self, method, path, data, headers, response):
        path = to_str(path)
        method = to_str(method)
        path = path.replace("#", "%23")

        # persist this API call to disk
        # super(ProxyListenerS3, self).return_response(method, path, data, headers, response)

        bucket_name = extract_bucket_name(headers, path)

        # POST requests to S3 may include a success_action_redirect or
        # success_action_status field, which should be used to redirect a
        # client to a new location.
        key = None
        if method == "POST":
            key, redirect_url = multipart_content.find_multipart_key_value(data, headers)
            if key and redirect_url:
                response.status_code = 303
                response.headers["Location"] = expand_redirect_url(redirect_url, key, bucket_name)
                LOG.debug(
                    "S3 POST {} to {}".format(response.status_code, response.headers["Location"])
                )

            expanded_data = multipart_content.expand_multipart_filename(data, headers)
            key, status_code = multipart_content.find_multipart_key_value(
                expanded_data, headers, "success_action_status"
            )

            if response.status_code == 201 and key:
                response._content = self.get_201_response(key, bucket_name)
                response.headers["Content-Length"] = str(len(response._content or ""))
                response.headers["Content-Type"] = "application/xml; charset=utf-8"
                return response
        if response.status_code == 416:
            if method == "GET":
                return self.error_response(
                    "The requested range cannot be satisfied.", "InvalidRange", 416
                )
            elif method == "HEAD":
                response.status_code = 200
                return response

        parsed = urlparse(path)
        bucket_name_in_host = uses_host_addressing(headers)
        should_send_notifications = all(
            [
                method in ("PUT", "POST", "DELETE"),
                "/" in path[1:] or bucket_name_in_host or key,
                # check if this is an actual put object request, because it could also be
                # a put bucket request with a path like this: /bucket_name/
                bucket_name_in_host
                or key
                or (len(path[1:].split("/")) > 1 and len(path[1:].split("/")[1]) > 0),
                self.is_query_allowable(method, parsed.query),
            ]
        )

        # get subscribers and send bucket notifications
        if should_send_notifications:
            # if we already have a good key, use it, otherwise examine the path
            if key:
                object_path = "/" + key
            elif bucket_name_in_host:
                object_path = parsed.path
            else:
                parts = parsed.path[1:].split("/", 1)
                object_path = parts[1] if parts[1][0] == "/" else "/%s" % parts[1]
            version_id = response.headers.get("x-amz-version-id", None)

            send_notifications(method, bucket_name, object_path, version_id, headers)

        # publish event for creation/deletion of buckets:
        if method in ("PUT", "DELETE") and (
            "/" not in path[1:] or len(path[1:].split("/")[1]) <= 0
        ):
            event_type = (
                event_publisher.EVENT_S3_CREATE_BUCKET
                if method == "PUT"
                else event_publisher.EVENT_S3_DELETE_BUCKET
            )
            event_publisher.fire_event(
                event_type, payload={"n": event_publisher.get_hash(bucket_name)}
            )

        # fix an upstream issue in moto S3 (see https://github.com/localstack/localstack/issues/382)
        if method == "PUT":
            if parsed.query == "policy":
                response._content = ""
                response.status_code = 204
                return response
            # when creating s3 bucket using aws s3api the return header contains 'Location' param
            if key is None:
                # if the bucket is created in 'us-east-1' the location header contains bucket as path
                # else the the header contains bucket url
                if aws_stack.get_region() == "us-east-1":
                    response.headers["Location"] = "/{}".format(bucket_name)
                else:
                    # Note: we need to set the correct protocol here
                    protocol = (
                        headers.get(constants.HEADER_LOCALSTACK_EDGE_URL, "").split("://")[0]
                        or "http"
                    )
                    response.headers["Location"] = "{}://{}.{}:{}/".format(
                        protocol,
                        bucket_name,
                        constants.S3_VIRTUAL_HOSTNAME,
                        config.EDGE_PORT,
                    )

        if response is not None:
            reset_content_length = False
            # append CORS headers and other annotations/patches to response
            append_cors_headers(
                bucket_name,
                request_method=method,
                request_headers=headers,
                response=response,
            )
            append_last_modified_headers(response=response)
            append_list_objects_marker(method, path, data, response)
            fix_location_constraint(response)
            fix_range_content_type(bucket_name, path, headers, response)
            fix_delete_objects_response(bucket_name, method, parsed, data, headers, response)
            fix_metadata_key_underscores(response=response)
            fix_creation_date(method, path, response=response)
            ret304_on_etag(data, headers, response)
            append_aws_request_troubleshooting_headers(response)
            fix_delimiter(data, headers, response)

            if method == "PUT":
                set_object_expiry(path, headers)

            # Remove body from PUT response on presigned URL
            # https://github.com/localstack/localstack/issues/1317
            if (
                method == "PUT"
                and int(response.status_code) < 400
                and (
                    "X-Amz-Security-Token=" in path
                    or "X-Amz-Credential=" in path
                    or "AWSAccessKeyId=" in path
                )
            ):
                response._content = ""
                reset_content_length = True

            response_content_str = None
            try:
                response_content_str = to_str(response._content)
            except Exception:
                pass

            # Honor response header overrides
            # https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
            if method == "GET":
                add_accept_range_header(response)
                add_response_metadata_headers(response)
                if is_object_expired(path):
                    return no_such_key_error(path, headers.get("x-amz-request-id"), 400)
                # AWS C# SDK uses get bucket acl to check the existence of the bucket
                # If not exists, raises a NoSuchBucket Error
                if bucket_name and "/?acl" in path:
                    exists, code, body = is_bucket_available(bucket_name)
                    if not exists:
                        return no_such_bucket(bucket_name, headers.get("x-amz-request-id"), 404)
                query_map = parse_qs(parsed.query, keep_blank_values=True)
                for param_name, header_name in ALLOWED_HEADER_OVERRIDES.items():
                    if param_name in query_map:
                        response.headers[header_name] = query_map[param_name][0]

            if response_content_str and response_content_str.startswith("<"):
                is_bytes = isinstance(response._content, bytes)
                response._content = response_content_str

                append_last_modified_headers(response=response, content=response_content_str)

                # We need to un-pretty-print the XML, otherwise we run into this issue with Spark:
                # https://github.com/jserver/mock-s3/pull/9/files
                # https://github.com/localstack/localstack/issues/183
                # Note: yet, we need to make sure we have a newline after the first line: <?xml ...>\n
                # Note: make sure to return XML docs verbatim: https://github.com/localstack/localstack/issues/1037
                if method != "GET" or not is_object_specific_request(path, headers):
                    response._content = re.sub(
                        r"([^\?])>\n\s*<",
                        r"\1><",
                        response_content_str,
                        flags=re.MULTILINE,
                    )

                # update Location information in response payload
                response._content = self._update_location(response._content, bucket_name)

                # convert back to bytes
                if is_bytes:
                    response._content = to_bytes(response._content)

                # fix content-type: https://github.com/localstack/localstack/issues/618
                #                   https://github.com/localstack/localstack/issues/549
                #                   https://github.com/localstack/localstack/issues/854

                if is_invalid_html_response(response.headers, response_content_str):
                    response.headers["Content-Type"] = "application/xml; charset=utf-8"

                reset_content_length = True

            # update Content-Length headers (fix https://github.com/localstack/localstack/issues/541)
            if method == "DELETE":
                reset_content_length = True

            if reset_content_length:
                response.headers["Content-Length"] = str(len(response._content or ""))

            # convert to chunked encoding, for compatibility with certain SDKs (e.g., AWS PHP SDK)
            convert_to_chunked_encoding(method, path, response)


class S3Provider(S3Api, ABC):
    def __init__(self):
        super().__init__()

        if not os.environ.get("MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"):
            os.environ["MOTO_S3_DEFAULT_KEY_BUFFER_SIZE"] = str(S3_MAX_FILE_SIZE_BYTES)

        self.s3_client = aws_stack.connect_to_service("s3")

    @staticmethod
    def error_response(message, code, status_code=400):
        result = {"Error": {"Code": code, "Message": message}}
        content = xmltodict.unparse(result)
        return S3Provider.xml_response(content, status_code=status_code)

    @staticmethod
    def xml_response(content, status_code=200):
        headers = {"Content-Type": "application/xml"}
        return requests_response(content, status_code=status_code, headers=headers)

    @staticmethod
    def _transform_path(context: RequestContext):
        # Hashes key names.
        path = context.request.path
        context.request.path = path.replace("#", "%23")

    @staticmethod
    def _is_static_website(context: RequestContext) -> bool:
        return is_static_website(context.request.headers)

    @staticmethod
    def _raise_if_invalid_bucket_name(context: RequestContext, bucket_name: Optional[BucketName]):
        # Support key names containing hashes (e.g., required by Amplify).
        path = context.request.path
        parsed_path = urlparse(path)
        if bucket_name and not re.match(BUCKET_NAME_REGEX, bucket_name):
            if len(parsed_path.path) <= 1:
                # return S3Provider.error_response(
                #     "Unable to extract valid bucket name. Please ensure that your AWS SDK is "
                #     + "configured to use path style addressing, or send a valid "
                #     + '<Bucket>.s3.localhost.localstack.cloud "Host" header',
                #     "InvalidBucketName",
                #     status_code=400,
                # )
                # TODO: check how to properly raise in providers.
                # TODO: there are no 'InvalidBucketName' exception type?
                raise NoSuchBucket(
                    "Unable to extract valid bucket name. Please ensure that your AWS SDK is "
                    + "configured to use path style addressing, or send a valid "
                    + '<Bucket>.s3.localhost.localstack.cloud "Host" header',
                    "InvalidBucketName",
                )

            # return S3Provider.error_response(
            #     "The specified bucket is not valid.",
            #     "InvalidBucketName",
            #     status_code=400,
            # )
            # TODO: check how to properly raise in providers.
            # TODO: there are no 'InvalidBucketName' exception type?
            # TODO: status code automatically set?
            raise NoSuchBucket("The specified bucket is not valid.", "InvalidBucketName")

    @staticmethod
    def _no_such_bucket(bucket_name: BucketName, request_id=None, status_code=404):
        # TODO: fix the response to match AWS bucket response when the webconfig is not set and bucket not exists
        result = {
            "Error": {
                "Code": "NoSuchBucket",
                "Message": "The specified bucket does not exist",
                "BucketName": bucket_name,
                "RequestId": request_id,
                "HostId": short_uid(),
            }
        }
        content = xmltodict.unparse(result)
        return S3Provider.xml_response(content, status_code=status_code)

    @staticmethod
    def _transform_content_types(context: RequestContext):
        method = context.request.method
        headers = context.request.headers
        content_type = headers.get(HEADER_CONTENT_TYPE, None)
        #
        # If no content-type is provided, 'binary/octet-stream' should be used
        # src: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
        if method == "PUT" and not content_type:
            headers[HEADER_CONTENT_TYPE] = BINARY_OCTET_STREAM

    @staticmethod
    def _fix_request_metadata_key_underscores(context: RequestContext):
        # fix for https://github.com/localstack/localstack/issues/1790
        headers = context.request.headers or {}
        underscore_replacement = "---"
        meta_header_prefix = "x-amz-meta-"
        prefix_len = len(meta_header_prefix)
        for key in list(headers.keys()):
            if key.lower().startswith(meta_header_prefix):
                key_new = meta_header_prefix + key[prefix_len:].replace("_", underscore_replacement)
                if key != key_new:
                    headers[key_new] = headers.pop(key)
        context.request.headers = headers

    @staticmethod
    def _append_metadata_headers(context: RequestContext):
        # Remap metadata query params (not supported in moto) to request headers.
        headers = context.request.headers

        # Extracting bucket name from the request.
        parsed_path = urlparse(context.request.path)

        # Parse query parameters.
        query = parsed_path.query
        query_map = parse_qs(query, keep_blank_values=True)

        for key, value in query_map.items():
            if key.lower().startswith(OBJECT_METADATA_KEY_PREFIX):
                if headers.get(key) is None:
                    headers[key] = value[0]

    @staticmethod
    def _transform_headers(context: RequestContext):
        if context.request.headers is None:
            context.request.headers = {}
        S3Provider._append_metadata_headers(context)
        S3Provider._fix_request_metadata_key_underscores(context)

    @staticmethod
    def _transform_request_context(context: RequestContext):
        S3Provider._transform_path(context)
        S3Provider._transform_headers(context)

    def _serve_static_website(self, context: RequestContext, bucket_name: BucketName):
        headers = context.request.headers
        path = context.request.path
        # check if bucket exists
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError:
            return self._no_such_bucket(bucket_name, headers.get("x-amz-request-id"), 404)

        def respond_with_key(status_code, key):
            obj = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            response_headers = {}

            if (
                "if-none-match" in headers
                and "ETag" in obj
                and obj["ETag"] in headers["if-none-match"]
            ):
                return requests_response(status_code=304, content="", headers=response_headers)
            if "WebsiteRedirectLocation" in obj:
                response_headers["location"] = obj["WebsiteRedirectLocation"]
                return requests_response(status_code=301, content="", headers=response_headers)
            if "ContentType" in obj:
                response_headers["content-type"] = obj["ContentType"]
            if "ETag" in obj:
                response_headers["etag"] = obj["ETag"]
            return requests_response(
                status_code=status_code, content=obj["Body"].read(), headers=response_headers
            )

        try:
            if path != "/":
                path = path.lstrip("/")
                return respond_with_key(status_code=200, key=path)
        except ClientError:
            LOG.debug("No such key found. %s", path)

        website_config = self.s3_client.get_bucket_website(Bucket=bucket_name)
        path_suffix = website_config.get("IndexDocument", {}).get("Suffix", "").lstrip("/")
        index_document = "%s/%s" % (path.rstrip("/"), path_suffix)
        try:
            return respond_with_key(status_code=200, key=index_document)
        except ClientError:
            error_document = website_config.get("ErrorDocument", {}).get("Key", "").lstrip("/")
            try:
                return respond_with_key(status_code=404, key=error_document)
            except ClientError:
                return requests_response(status_code=404, content="")

    def abort_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> AbortMultipartUploadOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def complete_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        upload_id: MultipartUploadId,
        multipart_upload: CompletedMultipartUpload = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> CompleteMultipartUploadOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def copy_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_type: ContentType = None,
        copy_source_if_match: CopySourceIfMatch = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        copy_source_if_none_match: CopySourceIfNoneMatch = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        expires: Expires = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write_acp: GrantWriteACP = None,
        metadata: Metadata = None,
        metadata_directive: MetadataDirective = None,
        tagging_directive: TaggingDirective = None,
        server_side_encryption: ServerSideEncryption = None,
        storage_class: StorageClass = None,
        website_redirect_location: WebsiteRedirectLocation = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        ssekms_key_id: SSEKMSKeyId = None,
        ssekms_encryption_context: SSEKMSEncryptionContext = None,
        bucket_key_enabled: BucketKeyEnabled = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        tagging: TaggingHeader = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        expected_bucket_owner: AccountId = None,
        expected_source_bucket_owner: AccountId = None,
    ) -> CopyObjectOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def create_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL = None,
        create_bucket_configuration: CreateBucketConfiguration = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        object_lock_enabled_for_bucket: ObjectLockEnabledForBucket = None,
        object_ownership: ObjectOwnership = None,
    ) -> CreateBucketOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)

        # Moto doesn't allow to put a location constraint on 'us-east-1'.
        location_constraint = create_bucket_configuration.get("LocationConstraint", None)
        if location_constraint == AWS_REGION_US_EAST_1:
            # Drop CreateBucketConfiguration bindings, inject compulsory fields, retail all others.
            binds_bs = context.request.data
            binds = xmltodict.parse(binds_bs)
            #
            binds["Bucket"] = bucket
            del binds["CreateBucketConfiguration"]
            #
            return call_moto_with_request(context, binds)

        return call_moto(context)

    def create_multipart_upload(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_type: ContentType = None,
        expires: Expires = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write_acp: GrantWriteACP = None,
        metadata: Metadata = None,
        server_side_encryption: ServerSideEncryption = None,
        storage_class: StorageClass = None,
        website_redirect_location: WebsiteRedirectLocation = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        ssekms_key_id: SSEKMSKeyId = None,
        ssekms_encryption_context: SSEKMSEncryptionContext = None,
        bucket_key_enabled: BucketKeyEnabled = None,
        request_payer: RequestPayer = None,
        tagging: TaggingHeader = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        expected_bucket_owner: AccountId = None,
    ) -> CreateMultipartUploadOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def delete_bucket(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def delete_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        mfa: MFA = None,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def delete_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectTaggingOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def delete_objects(
        self,
        context: RequestContext,
        bucket: BucketName,
        delete: Delete,
        mfa: MFA = None,
        request_payer: RequestPayer = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        expected_bucket_owner: AccountId = None,
    ) -> DeleteObjectsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def delete_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)

    def get_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAccelerateConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAclOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketAnalyticsConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketCorsOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketEncryptionOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_intelligent_tiering_configuration(
        self, context: RequestContext, bucket: BucketName, id: IntelligentTieringId
    ) -> GetBucketIntelligentTieringConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketInventoryConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketLifecycleOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketLifecycleConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_location(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketLocationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketLoggingOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketMetricsConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> NotificationConfigurationDeprecated:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> NotificationConfiguration:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketOwnershipControlsOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketPolicyOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_policy_status(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketPolicyStatusOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketReplicationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketRequestPaymentOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketTaggingOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketVersioningOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetBucketWebsiteOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        if_match: IfMatch = None,
        if_modified_since: IfModifiedSince = None,
        if_none_match: IfNoneMatch = None,
        if_unmodified_since: IfUnmodifiedSince = None,
        range: Range = None,
        response_cache_control: ResponseCacheControl = None,
        response_content_disposition: ResponseContentDisposition = None,
        response_content_encoding: ResponseContentEncoding = None,
        response_content_language: ResponseContentLanguage = None,
        response_content_type: ResponseContentType = None,
        response_expires: ResponseExpires = None,
        version_id: ObjectVersionId = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        part_number: PartNumber = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectAclOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectLegalHoldOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectLockConfigurationOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectRetentionOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> GetObjectTaggingOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_object_torrent(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> GetObjectTorrentOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def get_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        expected_bucket_owner: AccountId = None,
    ) -> GetPublicAccessBlockOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    # def head_bucket(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     expected_bucket_owner: AccountId = None,
    # ) -> None:
    #     self._transform_request_context(context)
    #     call_moto(context)

    # def head_object(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     if_match: IfMatch = None,
    #     if_modified_since: IfModifiedSince = None,
    #     if_none_match: IfNoneMatch = None,
    #     if_unmodified_since: IfUnmodifiedSince = None,
    #     range: Range = None,
    #     version_id: ObjectVersionId = None,
    #     sse_customer_algorithm: SSECustomerAlgorithm = None,
    #     sse_customer_key: SSECustomerKey = None,
    #     sse_customer_key_md5: SSECustomerKeyMD5 = None,
    #     request_payer: RequestPayer = None,
    #     part_number: PartNumber = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> HeadObjectOutput:
    #     self._transform_request_context(context)
    #     return call_moto(context)

    def list_bucket_analytics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketAnalyticsConfigurationsOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def list_bucket_intelligent_tiering_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
    ) -> ListBucketIntelligentTieringConfigurationsOutput:
        self._transform_request_context(context)
        if self._is_static_website(context):
            return self._serve_static_website(context, bucket)
        return call_moto(context)

    def list_bucket_inventory_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketInventoryConfigurationsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def list_bucket_metrics_configurations(
        self,
        context: RequestContext,
        bucket: BucketName,
        continuation_token: Token = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListBucketMetricsConfigurationsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def list_buckets(
        self,
        context: RequestContext,
    ) -> ListBucketsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def list_multipart_uploads(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        key_marker: KeyMarker = None,
        max_uploads: MaxUploads = None,
        prefix: Prefix = None,
        upload_id_marker: UploadIdMarker = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListMultipartUploadsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def list_object_versions(
        self,
        context: RequestContext,
        bucket: BucketName,
        delimiter: Delimiter = None,
        encoding_type: EncodingType = None,
        key_marker: KeyMarker = None,
        max_keys: MaxKeys = None,
        prefix: Prefix = None,
        version_id_marker: VersionIdMarker = None,
        expected_bucket_owner: AccountId = None,
    ) -> ListObjectVersionsOutput:
        self._transform_request_context(context)
        return call_moto(context)

    # def list_objects(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     marker: Marker = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsOutput:
    #     self._transform_request_context(context)
    #     return call_moto(context)

    # def list_objects_v2(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     delimiter: Delimiter = None,
    #     encoding_type: EncodingType = None,
    #     max_keys: MaxKeys = None,
    #     prefix: Prefix = None,
    #     continuation_token: Token = None,
    #     fetch_owner: FetchOwner = None,
    #     start_after: StartAfter = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListObjectsV2Output:
    #     self._transform_request_context(context)
    #     return call_moto(context)

    # def list_parts(
    #     self,
    #     context: RequestContext,
    #     bucket: BucketName,
    #     key: ObjectKey,
    #     upload_id: MultipartUploadId,
    #     max_parts: MaxParts = None,
    #     part_number_marker: PartNumberMarker = None,
    #     request_payer: RequestPayer = None,
    #     expected_bucket_owner: AccountId = None,
    # ) -> ListPartsOutput:
    #     self._transform_request_context(context)
    #     return call_moto(context)

    def put_bucket_accelerate_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        accelerate_configuration: AccelerateConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        acl: BucketCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_analytics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: AnalyticsId,
        analytics_configuration: AnalyticsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_cors(
        self,
        context: RequestContext,
        bucket: BucketName,
        cors_configuration: CORSConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_encryption(
        self,
        context: RequestContext,
        bucket: BucketName,
        server_side_encryption_configuration: ServerSideEncryptionConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_intelligent_tiering_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: IntelligentTieringId,
        intelligent_tiering_configuration: IntelligentTieringConfiguration,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_inventory_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: InventoryId,
        inventory_configuration: InventoryConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_lifecycle(
        self,
        context: RequestContext,
        bucket: BucketName,
        content_md5: ContentMD5 = None,
        lifecycle_configuration: LifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_lifecycle_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        lifecycle_configuration: BucketLifecycleConfiguration = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_logging(
        self,
        context: RequestContext,
        bucket: BucketName,
        bucket_logging_status: BucketLoggingStatus,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_metrics_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        id: MetricsId,
        metrics_configuration: MetricsConfiguration,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_notification(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfigurationDeprecated,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_notification_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        notification_configuration: NotificationConfiguration,
        expected_bucket_owner: AccountId = None,
        skip_destination_validation: SkipValidation = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_ownership_controls(
        self,
        context: RequestContext,
        bucket: BucketName,
        ownership_controls: OwnershipControls,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        policy: Policy,
        content_md5: ContentMD5 = None,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_replication(
        self,
        context: RequestContext,
        bucket: BucketName,
        replication_configuration: ReplicationConfiguration,
        content_md5: ContentMD5 = None,
        token: ObjectLockToken = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_request_payment(
        self,
        context: RequestContext,
        bucket: BucketName,
        request_payment_configuration: RequestPaymentConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        tagging: Tagging,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_versioning(
        self,
        context: RequestContext,
        bucket: BucketName,
        versioning_configuration: VersioningConfiguration,
        content_md5: ContentMD5 = None,
        mfa: MFA = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_bucket_website(
        self,
        context: RequestContext,
        bucket: BucketName,
        website_configuration: WebsiteConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def put_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        body: Body = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        content_type: ContentType = None,
        expires: Expires = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write_acp: GrantWriteACP = None,
        metadata: Metadata = None,
        server_side_encryption: ServerSideEncryption = None,
        storage_class: StorageClass = None,
        website_redirect_location: WebsiteRedirectLocation = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        ssekms_key_id: SSEKMSKeyId = None,
        ssekms_encryption_context: SSEKMSEncryptionContext = None,
        bucket_key_enabled: BucketKeyEnabled = None,
        request_payer: RequestPayer = None,
        tagging: TaggingHeader = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_object_acl(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        acl: ObjectCannedACL = None,
        access_control_policy: AccessControlPolicy = None,
        content_md5: ContentMD5 = None,
        grant_full_control: GrantFullControl = None,
        grant_read: GrantRead = None,
        grant_read_acp: GrantReadACP = None,
        grant_write: GrantWrite = None,
        grant_write_acp: GrantWriteACP = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectAclOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_object_legal_hold(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        legal_hold: ObjectLockLegalHold = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLegalHoldOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_object_lock_configuration(
        self,
        context: RequestContext,
        bucket: BucketName,
        object_lock_configuration: ObjectLockConfiguration = None,
        request_payer: RequestPayer = None,
        token: ObjectLockToken = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectLockConfigurationOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_object_retention(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        retention: ObjectLockRetention = None,
        request_payer: RequestPayer = None,
        version_id: ObjectVersionId = None,
        bypass_governance_retention: BypassGovernanceRetention = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> PutObjectRetentionOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_object_tagging(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        tagging: Tagging,
        version_id: ObjectVersionId = None,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
        request_payer: RequestPayer = None,
    ) -> PutObjectTaggingOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def put_public_access_block(
        self,
        context: RequestContext,
        bucket: BucketName,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        content_md5: ContentMD5 = None,
        expected_bucket_owner: AccountId = None,
    ) -> None:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        call_moto(context)

    def restore_object(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        restore_request: RestoreRequest = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> RestoreObjectOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def select_object_content(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        expression: Expression,
        expression_type: ExpressionType,
        input_serialization: InputSerialization,
        output_serialization: OutputSerialization,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_progress: RequestProgress = None,
        scan_range: ScanRange = None,
        expected_bucket_owner: AccountId = None,
    ) -> SelectObjectContentOutput:
        self._transform_request_context(context)
        return call_moto(context)

    def upload_part(
        self,
        context: RequestContext,
        bucket: BucketName,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        body: Body = None,
        content_length: ContentLength = None,
        content_md5: ContentMD5 = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
    ) -> UploadPartOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def upload_part_copy(
        self,
        context: RequestContext,
        bucket: BucketName,
        copy_source: CopySource,
        key: ObjectKey,
        part_number: PartNumber,
        upload_id: MultipartUploadId,
        copy_source_if_match: CopySourceIfMatch = None,
        copy_source_if_modified_since: CopySourceIfModifiedSince = None,
        copy_source_if_none_match: CopySourceIfNoneMatch = None,
        copy_source_if_unmodified_since: CopySourceIfUnmodifiedSince = None,
        copy_source_range: CopySourceRange = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        sse_customer_key: SSECustomerKey = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        copy_source_sse_customer_algorithm: CopySourceSSECustomerAlgorithm = None,
        copy_source_sse_customer_key: CopySourceSSECustomerKey = None,
        copy_source_sse_customer_key_md5: CopySourceSSECustomerKeyMD5 = None,
        request_payer: RequestPayer = None,
        expected_bucket_owner: AccountId = None,
        expected_source_bucket_owner: AccountId = None,
    ) -> UploadPartCopyOutput:
        self._transform_request_context(context)
        self._transform_content_types(context)
        S3Provider._raise_if_invalid_bucket_name(context, bucket_name=bucket)
        return call_moto(context)

    def write_get_object_response(
        self,
        context: RequestContext,
        request_route: RequestRoute,
        request_token: RequestToken,
        body: Body = None,
        status_code: GetObjectResponseStatusCode = None,
        error_code: ErrorCode = None,
        error_message: ErrorMessage = None,
        accept_ranges: AcceptRanges = None,
        cache_control: CacheControl = None,
        content_disposition: ContentDisposition = None,
        content_encoding: ContentEncoding = None,
        content_language: ContentLanguage = None,
        content_length: ContentLength = None,
        content_range: ContentRange = None,
        content_type: ContentType = None,
        delete_marker: DeleteMarker = None,
        e_tag: ETag = None,
        expires: Expires = None,
        expiration: Expiration = None,
        last_modified: LastModified = None,
        missing_meta: MissingMeta = None,
        metadata: Metadata = None,
        object_lock_mode: ObjectLockMode = None,
        object_lock_legal_hold_status: ObjectLockLegalHoldStatus = None,
        object_lock_retain_until_date: ObjectLockRetainUntilDate = None,
        parts_count: PartsCount = None,
        replication_status: ReplicationStatus = None,
        request_charged: RequestCharged = None,
        restore: Restore = None,
        server_side_encryption: ServerSideEncryption = None,
        sse_customer_algorithm: SSECustomerAlgorithm = None,
        ssekms_key_id: SSEKMSKeyId = None,
        sse_customer_key_md5: SSECustomerKeyMD5 = None,
        storage_class: StorageClass = None,
        tag_count: TagCount = None,
        version_id: ObjectVersionId = None,
        bucket_key_enabled: BucketKeyEnabled = None,
    ) -> None:
        self._transform_request_context(context)
        call_moto(context)


def s3_update_acls(self, request, query, bucket_name, key_name):
    # fix for - https://github.com/localstack/localstack/issues/1733
    #         - https://github.com/localstack/localstack/issues/1170
    acl_key = "acl|%s|%s" % (bucket_name, key_name)
    acl = self._acl_from_headers(request.headers)
    if acl:
        TMP_STATE[acl_key] = acl
    if not query.get("uploadId"):
        return
    bucket = self.backend.get_bucket(bucket_name)
    key = bucket and self.backend.get_object(bucket_name, key_name)
    if not key:
        return
    acl = acl or TMP_STATE.pop(acl_key, None) or bucket.acl
    if acl:
        key.set_acl(acl)


# patch S3Bucket.create_bucket(..)
@patch(s3_models.s3_backend.create_bucket)
def create_bucket(self, fn, bucket_name, region_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    return fn(bucket_name, region_name, *args, **kwargs)


# patch S3Bucket.get_bucket(..)
@patch(s3_models.s3_backend.get_bucket)
def get_bucket(self, fn, bucket_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    if bucket_name == config.BUCKET_MARKER_LOCAL:
        return None
    return fn(bucket_name, *args, **kwargs)


@patch(s3_responses.ResponseObject._bucket_response_head)
def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
    code, headers, body = fn(self, bucket_name, *args, **kwargs)
    bucket = s3_models.s3_backend.get_bucket(bucket_name)
    headers["x-amz-bucket-region"] = bucket.region_name
    return code, headers, body


@patch(s3_responses.ResponseObject._bucket_response_get)
def _bucket_response_get(fn, self, bucket_name, querystring, *args, **kwargs):
    result = fn(self, bucket_name, querystring, *args, **kwargs)
    # for some reason in the "get-bucket-location" call, moto doesn't return a code, headers, body triple as a result
    if isinstance(result, tuple) and len(result) == 3:
        code, headers, body = result
        bucket = s3_models.s3_backend.get_bucket(bucket_name)
        headers["x-amz-bucket-region"] = bucket.region_name
    return result


# patch S3Bucket.get_bucket(..)
@patch(s3_models.s3_backend.delete_bucket)
def delete_bucket(self, fn, bucket_name, *args, **kwargs):
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    s3_listener.remove_bucket_notification(bucket_name)
    return fn(bucket_name, *args, **kwargs)


# patch _key_response_post(..)
@patch(s3_responses.S3ResponseInstance._key_response_post)
def s3_key_response_post(self, fn, request, body, bucket_name, query, key_name, *args, **kwargs):
    result = fn(request, body, bucket_name, query, key_name, *args, **kwargs)
    s3_update_acls(self, request, query, bucket_name, key_name)
    try:
        if query.get("uploadId"):
            if (bucket_name, key_name) in TMP_TAG:
                key = self.backend.get_object(bucket_name, key_name)
                self.backend.set_key_tags(key, TMP_TAG.get((bucket_name, key_name), None), key_name)
                TMP_TAG.pop((bucket_name, key_name))
    except Exception:
        pass
    if query.get("uploads") and request.headers.get("X-Amz-Tagging"):
        tags = self._tagging_from_headers(request.headers)
        TMP_TAG[(bucket_name, key_name)] = tags
    return result


# patch _key_response_put(..)
@patch(s3_responses.S3ResponseInstance._key_response_put)
def s3_key_response_put(
    self, fn, request, body, bucket_name, query, key_name, headers, *args, **kwargs
):
    result = fn(request, body, bucket_name, query, key_name, headers, *args, **kwargs)
    s3_update_acls(self, request, query, bucket_name, key_name)
    return result


# patch DeleteObjectTagging
@patch(s3_responses.S3ResponseInstance._key_response_delete)
def s3_key_response_delete(self, fn, headers, bucket_name, query, key_name, *args, **kwargs):
    # Fixes https://github.com/localstack/localstack/issues/1083
    if query.get("tagging"):
        self._set_action("KEY", "DELETE", query)
        self._authenticate_and_authorize_s3_action()
        key = self.backend.get_object(bucket_name, key_name)
        key.tags = {}
        self.backend.tagger.delete_all_tags_for_resource(key.arn)
        return 204, {}, ""
    result = fn(headers, bucket_name, query, key_name, *args, **kwargs)
    return result


action_map = s3_responses.ACTION_MAP
action_map["KEY"]["DELETE"]["tagging"] = (
    action_map["KEY"]["DELETE"].get("tagging") or "DeleteObjectTagging"
)


# patch _key_response_get(..)
# https://github.com/localstack/localstack/issues/2724
class InvalidObjectState(S3ClientError):
    code = 400

    def __init__(self, *args, **kwargs):
        super(InvalidObjectState, self).__init__(
            "InvalidObjectState",
            "The operation is not valid for the object's storage class.",
            *args,
            **kwargs,
        )


@patch(s3_responses.S3ResponseInstance._key_response_get)
def s3_key_response_get(self, fn, bucket_name, query, key_name, headers, *args, **kwargs):
    resp_status, resp_headers, resp_value = fn(
        bucket_name, query, key_name, headers, *args, **kwargs
    )

    if resp_headers.get("x-amz-storage-class") == "DEEP_ARCHIVE" and not resp_headers.get(
        "x-amz-restore"
    ):
        raise InvalidObjectState()

    return resp_status, resp_headers, resp_value


# patch truncate_result
@patch(s3_responses.S3ResponseInstance._truncate_result)
def s3_truncate_result(self, fn, result_keys, max_keys):
    return fn(result_keys, max_keys or 1000)


# patch _bucket_response_delete_keys(..)
# https://github.com/localstack/localstack/issues/2077
# TODO: check if patch still needed!
s3_delete_keys_response_template = """<?xml version="1.0" encoding="UTF-8"?>
 <DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
 {% for k in deleted %}
 <Deleted>
 <Key>{{k.key}}</Key>
 <VersionId>{{k.version_id}}</VersionId>
 </Deleted>
 {% endfor %}
 {% for k in delete_errors %}
 <Error>
 <Key>{{k}}</Key>
 </Error>
 {% endfor %}
 </DeleteResult>"""


@patch(s3_responses.S3ResponseInstance._bucket_response_delete_keys, pass_target=False)
def s3_bucket_response_delete_keys(self, request, body, bucket_name):
    template = self.response_template(s3_delete_keys_response_template)
    elements = minidom.parseString(body).getElementsByTagName("Object")
    if len(elements) == 0:
        raise MalformedXML()

    deleted_names = []
    error_names = []

    keys = []
    for element in elements:
        if len(element.getElementsByTagName("VersionId")) == 0:
            version_id = None
        else:
            version_id = element.getElementsByTagName("VersionId")[0].firstChild.nodeValue

        keys.append(
            {
                "key_name": element.getElementsByTagName("Key")[0].firstChild.nodeValue,
                "version_id": version_id,
            }
        )

    for k in keys:
        key_name = k["key_name"]
        version_id = k["version_id"]
        success = self.backend.delete_object(bucket_name, undo_clean_key_name(key_name), version_id)

        if success:
            deleted_names.append({"key": key_name, "version_id": version_id})
        else:
            error_names.append(key_name)

    return (
        200,
        {},
        template.render(deleted=deleted_names, delete_errors=error_names),
    )


# Patch _handle_range_header(..)
# https://github.com/localstack/localstack/issues/2146


@patch(s3_responses.S3ResponseInstance._handle_range_header)
def s3_response_handle_range_header(self, fn, request, headers, response_content):
    rs_code, rs_headers, rs_content = fn(request, headers, response_content)
    if rs_code == 206:
        for k in ["ETag", "last-modified"]:
            v = headers.get(k)
            if v and not rs_headers.get(k):
                rs_headers[k] = v

    return rs_code, rs_headers, rs_content


# Patch utils_is_delete_keys
# https://github.com/localstack/localstack/issues/2866
# https://github.com/localstack/localstack/issues/2850
# https://github.com/localstack/localstack/issues/3931
# https://github.com/localstack/localstack/issues/4015
utils_is_delete_keys_orig = s3bucket_path_utils.is_delete_keys


def utils_is_delete_keys(request, path, bucket_name):
    return "/" + bucket_name + "?delete=" in path or utils_is_delete_keys_orig(
        request, path, bucket_name
    )


@patch(s3_responses.S3ResponseInstance.is_delete_keys, pass_target=False)
def s3_response_is_delete_keys(self, request, path, bucket_name):
    if self.subdomain_based_buckets(request):
        # Temporary fix until moto supports x-id and DeleteObjects (#3931)
        query = self._get_querystring(request.url)
        is_delete_keys_v3 = (
            query and ("delete" in query) and get_safe(query, "$.x-id.0") == "DeleteObjects"
        )
        return is_delete_keys_v3 or is_delete_keys(request, path, bucket_name)
    else:
        return utils_is_delete_keys(request, path, bucket_name)


@patch(s3_responses.S3ResponseInstance.parse_bucket_name_from_url, pass_target=False)
def parse_bucket_name_from_url(self, request, url):
    path = urlparse(url).path
    return s3_utils.extract_bucket_name(request.headers, path)


@patch(s3_responses.S3ResponseInstance.subdomain_based_buckets, pass_target=False)
def subdomain_based_buckets(self, request):
    return s3_utils.uses_host_addressing(request.headers)


@patch(s3_responses.S3ResponseInstance._bucket_response_get)
def s3_bucket_response_get(self, fn, bucket_name, querystring):
    try:
        return fn(bucket_name, querystring)
    except NotImplementedError:
        if "uploads" not in querystring:
            raise

        multiparts = list(self.backend.get_all_multiparts(bucket_name).values())
        if "prefix" in querystring:
            prefix = querystring.get("prefix", [None])[0]
            multiparts = [upload for upload in multiparts if upload.key_name.startswith(prefix)]

        upload_ids = [upload_id for upload_id in querystring.get("uploads") if upload_id]
        if upload_ids:
            multiparts = [upload for upload in multiparts if upload.id in upload_ids]

        template = self.response_template(S3_ALL_MULTIPARTS)
        return template.render(bucket_name=bucket_name, uploads=multiparts)


@patch(s3_models.s3_backend.copy_object)
def copy_object(
    self,
    fn,
    src_key,
    dest_bucket_name,
    dest_key_name,
    *args,
    **kwargs,
):
    fn(
        src_key,
        dest_bucket_name,
        dest_key_name,
        *args,
        **kwargs,
    )
    key = self.get_object(dest_bucket_name, dest_key_name)
    # reset etag
    key._etag = None
