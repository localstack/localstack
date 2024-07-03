import copy
import io
import json
import re
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, Iterator, List, Optional
from xml.etree import ElementTree

import pytest
from botocore.awsrequest import HeadersDict
from botocore.endpoint import convert_to_response_dict
from botocore.parsers import ResponseParser, create_parser

# cbor2: explicitly load from private _decoder module to avoid using the (non-patched) C-version
from cbor2._decoder import loads as cbor2_loads
from dateutil.tz import tzlocal, tzutc
from requests.models import Response as RequestsResponse
from urllib3 import HTTPResponse as UrlLibHttpResponse
from werkzeug.datastructures import Headers
from werkzeug.wrappers import ResponseStream

from localstack.aws.api import CommonServiceException, ServiceException
from localstack.aws.api.dynamodb import (
    AttributeValue,
    CancellationReason,
    TransactionCanceledException,
)
from localstack.aws.api.kinesis import GetRecordsOutput, Record
from localstack.aws.api.lambda_ import ResourceNotFoundException
from localstack.aws.api.route53 import NoSuchHostedZone
from localstack.aws.api.sns import VerificationException
from localstack.aws.api.sqs import (
    InvalidMessageContents,
    ReceiptHandleIsInvalid,
    UnsupportedOperation,
)
from localstack.aws.api.sts import Credentials, GetSessionTokenResponse
from localstack.aws.protocol.serializer import (
    ProtocolSerializerError,
    QueryResponseSerializer,
    UnknownSerializerError,
    aws_response_serializer,
    create_serializer,
)
from localstack.aws.spec import load_service
from localstack.constants import APPLICATION_AMZ_CBOR_1_1
from localstack.http import Request, Response
from localstack.utils.common import to_str
from localstack.utils.strings import long_uid

_skip_assert = {}


def _botocore_serializer_integration_test(
    service: str,
    action: str,
    response: dict,
    status_code=200,
    expected_response_content: dict = None,
) -> dict:
    """
    Performs an integration test for the serializer using botocore as parser.
    It executes the following steps:
    - Load the given service (f.e. "sqs")
    - Serialize the response with the appropriate serializer from the AWS Serivce Framework
    - Parse the serialized response using the botocore parser
    - Checks if the metadata is correct (status code, requestID,...)
    - Checks if the parsed response content is equal to the input to the serializer

    :param service: to load the correct service specification, serializer, and parser
    :param action: to load the correct service specification, serializer, and parser
    :param response: which should be serialized and tested against
    :param status_code: Optional - expected status code of the response - defaults to 200
    :param expected_response_content: Optional - if the input data ("response") differs from the actually expected data
                                      (because f.e. it contains None values)
    :return: boto-parsed serialized response
    """

    # Load the appropriate service
    service = load_service(service)

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    # The serializer changes the incoming dict, therefore copy it before passing it to the serializer
    response_to_parse = copy.deepcopy(response)
    serialized_response = response_serializer.serialize_to_response(
        response_to_parse, service.operation_model(action), None, long_uid()
    )

    # Use the parser from botocore to parse the serialized response
    response_parser = create_parser(service.protocol)
    parsed_response = response_parser.parse(
        serialized_response.to_readonly_response_dict(),
        service.operation_model(action).output_shape,
    )

    return_response = copy.deepcopy(parsed_response)

    # Check if the result is equal to the initial response params
    assert "ResponseMetadata" in parsed_response
    assert "HTTPStatusCode" in parsed_response["ResponseMetadata"]
    assert parsed_response["ResponseMetadata"]["HTTPStatusCode"] == status_code
    assert "RequestId" in parsed_response["ResponseMetadata"]
    assert len(parsed_response["ResponseMetadata"]["RequestId"]) == 36
    del parsed_response["ResponseMetadata"]

    if expected_response_content is None:
        expected_response_content = response
    if expected_response_content is not _skip_assert:
        assert parsed_response == expected_response_content

    return return_response


def _botocore_error_serializer_integration_test(
    service_model_name: str,
    action: str,
    exception: ServiceException,
    code: str,
    status_code: int,
    message: Optional[str],
    is_sender_fault: bool = False,
    **additional_error_fields: Dict[str, Any],
) -> dict:
    """
    Performs an integration test for the error serialization using botocore as parser.
    It executes the following steps:
    - Load the given service (f.e. "sqs")
    - Serialize the _error_ response with the appropriate serializer from the AWS Serivce Framework
    - Parse the serialized error response using the botocore parser
    - Checks if the metadata is correct (status code, requestID,...)
    - Checks if the parsed error response content is correct

    :param service_model_name: to load the correct service specification, serializer, and parser
    :param action: to load the correct service specification, serializer, and parser
    :param exception: which should be serialized and tested against
    :param code: expected "code" of the exception (i.e. the AWS specific exception ID, f.e.
                 "CloudFrontOriginAccessIdentityAlreadyExists")
    :param status_code: expected HTTP response status code
    :param message: expected error message
    :param is_sender_fault: expected fault type is sender
    :param additional_error_fields: additional fields which need to be present (for exception shapes with members)
    :return: boto-parsed serialized error response
    """

    # Load the appropriate service
    service = load_service(service_model_name)

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model(action), None, long_uid()
    )

    # Use the parser from botocore to parse the serialized response
    response_dict = serialized_response.to_readonly_response_dict()

    # botocore converts the headers to lower-case keys
    # f.e. needed for x-amzn-errortype
    response_dict["headers"] = HeadersDict(response_dict["headers"])

    response_parser: ResponseParser = create_parser(service.protocol)
    parsed_response = response_parser.parse(
        response_dict,
        service.operation_model(action).output_shape,
    )
    # Add the modeled error shapes
    error_shape = service.shape_for_error_code(exception.code)
    modeled_parse = response_parser.parse(response_dict, error_shape)
    parsed_response.update(modeled_parse)

    # Check if the result is equal to the initial response params
    assert "Error" in parsed_response
    assert "Code" in parsed_response["Error"]
    assert "Message" in parsed_response["Error"]
    assert parsed_response["Error"]["Code"] == code
    assert parsed_response["Error"]["Message"] == message

    assert "ResponseMetadata" in parsed_response
    assert "RequestId" in parsed_response["ResponseMetadata"]
    assert len(parsed_response["ResponseMetadata"]["RequestId"]) == 36
    assert "HTTPStatusCode" in parsed_response["ResponseMetadata"]
    assert parsed_response["ResponseMetadata"]["HTTPStatusCode"] == status_code
    type = parsed_response["Error"].get("Type")
    if is_sender_fault:
        assert type == "Sender"
    else:
        assert type is None
    if additional_error_fields:
        for key, value in additional_error_fields.items():
            assert key in parsed_response
            assert parsed_response[key] == value
    return parsed_response


def _botocore_event_streaming_test(
    service: str, action: str, response: dict, response_root_tag: str, expected_events: List[dict]
):
    """
    Tests the serialization of event streaming responses using botocore.

    :param service: to load the correct service specification, serializer, and parser
    :param action: to load the correct service specification, serializer, and parser
    :param response: which should be serialized
    :param response_root_tag: name of the root element in the response
    :param expected_events: events which are streamed and should be contained in the fully streamed and deserialized response
    :return: None
    """
    # Serialize the response
    service = load_service(service)
    operation_model = service.operation_model(action)
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_to_response(
        response, operation_model, None, long_uid()
    )

    # Convert the Werkzeug response from our serializer to a response botocore can work with
    urllib_response = UrlLibHttpResponse(
        body=_iterable_to_stream(serialized_response.response),
        headers={
            entry_tuple[0].lower(): entry_tuple[1] for entry_tuple in serialized_response.headers
        },
        status=serialized_response.status_code,
        decode_content=False,
        preload_content=False,
    )
    requests_response = RequestsResponse()
    requests_response.headers = urllib_response.headers
    requests_response.status_code = urllib_response.status
    requests_response.raw = urllib_response
    botocore_response = convert_to_response_dict(requests_response, operation_model)

    # parse the response using botocore
    response_parser: ResponseParser = create_parser(service.protocol)
    parsed_response = response_parser.parse(
        botocore_response,
        operation_model.output_shape,
    )

    # check that the response contains the event stream
    assert response_root_tag in parsed_response

    # fetch all events and check their content
    actual_events = list(parsed_response[response_root_tag])
    assert len(actual_events) == len(expected_events)
    assert actual_events == expected_events


def test_rest_xml_serializer_cloudfront_with_botocore():
    parameters = {
        "TestResult": {
            "FunctionSummary": {
                "Name": "string",
                "Status": "string",
                "FunctionConfig": {"Comment": "string", "Runtime": "cloudfront-js-1.0"},
                "FunctionMetadata": {
                    "FunctionARN": "string",
                    "Stage": "LIVE",
                    # Test the timestamp precision by adding hours, minutes, seconds and some milliseconds
                    # (as microseconds).
                    "CreatedTime": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
                    "LastModifiedTime": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
                },
            },
            "ComputeUtilization": "string",
            "FunctionExecutionLogs": [
                "string",
            ],
            "FunctionErrorMessage": "string",
            "FunctionOutput": "string",
        }
    }
    _botocore_serializer_integration_test("cloudfront", "TestFunction", parameters)


def test_rest_xml_serializer_route53_with_botocore():
    parameters = {
        "HostedZone": {
            "Id": "/hostedzone/9WXI4LV03NAZVS1",
            "Name": "fuu.",
            "Config": {"PrivateZone": False},
            "ResourceRecordSetCount": 0,
        },
        "DelegationSet": {"NameServers": ["dns.localhost.localstack.cloud"]},
    }
    _botocore_serializer_integration_test("route53", "CreateHostedZone", parameters, 201)


def test_rest_xml_serializer_s3_with_botocore():
    parameters = {
        "AnalyticsConfiguration": {
            "Id": "string",
            "Filter": {
                "Prefix": "string",
                "Tag": {"Key": "string", "Value": "string"},
                "And": {
                    "Prefix": "string",
                    "Tags": [
                        {"Key": "string", "Value": "string"},
                    ],
                },
            },
            "StorageClassAnalysis": {
                "DataExport": {
                    "OutputSchemaVersion": "V_1",
                    "Destination": {
                        "S3BucketDestination": {
                            "Format": "CSV",
                            "BucketAccountId": "string",
                            "Bucket": "string",
                            "Prefix": "string",
                        }
                    },
                }
            },
        }
    }
    _botocore_serializer_integration_test("s3", "GetBucketAnalyticsConfiguration", parameters)


def test_rest_xml_serializer_s3_2_with_botocore():
    # These date fields in this response are encoded in the header. The max precision is seconds.
    parameters = {
        "Body": "body",
        "DeleteMarker": True,
        "AcceptRanges": "string",
        "Expiration": "string",
        "Restore": "string",
        "LastModified": datetime(2015, 1, 1, 23, 59, 59, tzinfo=tzutc()),
        "ContentLength": 4,
        "ETag": "string",
        "MissingMeta": 123,
        "VersionId": "string",
        "CacheControl": "string",
        "ContentDisposition": "string",
        "ContentEncoding": "string",
        "ContentLanguage": "string",
        "ContentRange": "string",
        "ContentType": "string",
        "Expires": datetime(2015, 1, 1, 23, 59, 59, tzinfo=tzutc()),
        "WebsiteRedirectLocation": "string",
        "ServerSideEncryption": "AES256",
        "Metadata": {"string": "string"},
        "SSECustomerAlgorithm": "string",
        "SSECustomerKeyMD5": "string",
        "SSEKMSKeyId": "string",
        "BucketKeyEnabled": True | False,
        "StorageClass": "STANDARD",
        "RequestCharged": "requester",
        "ReplicationStatus": "COMPLETE",
        "PartsCount": 123,
        "TagCount": 123,
        "ObjectLockMode": "GOVERNANCE",
        "ObjectLockRetainUntilDate": datetime(2015, 1, 1, 23, 59, 59, tzinfo=tzutc()),
        "ObjectLockLegalHoldStatus": "ON",
        "StatusCode": 200,
    }
    _botocore_serializer_integration_test("s3", "GetObject", parameters)


def test_query_serializer_cloudformation_with_botocore():
    parameters = {
        "StackResourceDrift": {
            "StackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/MyStack/d0a825a0-e4cd-xmpl-b9fb-061c69e99204",
            "LogicalResourceId": "MyFunction",
            "PhysicalResourceId": "my-function-SEZV4XMPL4S5",
            "ResourceType": "AWS::Lambda::Function",
            "ExpectedProperties": '{"Description":"Write a file to S3.","Environment":{"Variables":{"bucket":"my-stack-bucket-1vc62xmplgguf"}},"Handler":"index.handler","MemorySize":128,"Role":"arn:aws:iam::123456789012:role/my-functionRole-HIZXMPLEOM9E","Runtime":"nodejs10.x","Tags":[{"Key":"lambda:createdBy","Value":"SAM"}],"Timeout":900,"TracingConfig":{"Mode":"Active"}}',
            "ActualProperties": '{"Description":"Write a file to S3.","Environment":{"Variables":{"bucket":"my-stack-bucket-1vc62xmplgguf"}},"Handler":"index.handler","MemorySize":256,"Role":"arn:aws:iam::123456789012:role/my-functionRole-HIZXMPLEOM9E","Runtime":"nodejs10.x","Tags":[{"Key":"lambda:createdBy","Value":"SAM"}],"Timeout":22,"TracingConfig":{"Mode":"Active"}}',
            "PropertyDifferences": [
                {
                    "PropertyPath": "/MemorySize",
                    "ExpectedValue": "128",
                    "ActualValue": "256",
                    "DifferenceType": "NOT_EQUAL",
                },
                {
                    "PropertyPath": "/Timeout",
                    "ExpectedValue": "900",
                    "ActualValue": "22",
                    "DifferenceType": "NOT_EQUAL",
                },
            ],
            "StackResourceDriftStatus": "MODIFIED",
            "Timestamp": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
        }
    }
    _botocore_serializer_integration_test("cloudformation", "DetectStackResourceDrift", parameters)


def test_query_serializer_redshift_with_botocore():
    parameters = {
        "Marker": "string",
        "ClusterDbRevisions": [
            {
                "ClusterIdentifier": "string",
                "CurrentDatabaseRevision": "string",
                "DatabaseRevisionReleaseDate": datetime(
                    2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()
                ),
                "RevisionTargets": [
                    {
                        "DatabaseRevision": "string",
                        "Description": "string",
                        "DatabaseRevisionReleaseDate": datetime(
                            2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()
                        ),
                    },
                ],
            },
        ],
    }
    _botocore_serializer_integration_test("redshift", "DescribeClusterDbRevisions", parameters)


def test_query_serializer_sqs_empty_return_shape_with_botocore():
    _botocore_serializer_integration_test("sqs", "SetQueueAttributes", {})


def test_query_serializer_sqs_flattened_list_with_botocore():
    response = {
        "QueueUrls": [
            "http://localhost:4566/000000000000/myqueue1",
            "http://localhost:4566/000000000000/myqueue2",
        ]
    }
    _botocore_serializer_integration_test("sqs", "ListQueues", response)


def test_query_serializer_sqs_flattened_map_with_botocore():
    response = {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:us-east-1:000000000000:test-queue-01",
            "DelaySeconds": "0",
        }
    }
    _botocore_serializer_integration_test("sqs", "GetQueueAttributes", response)


def test_query_serializer_sqs_flattened_list_map_with_botocore():
    response = {
        "Messages": [
            {
                "MessageId": "ac9baa5c-13b1-4206-aa28-2ac45ae168af",
                "ReceiptHandle": "AQEBZ14sCjWJuot0T8G2Eg3S8C+sJGg+QRKYCJjfd8iiOsrPfUzbXSjlQquT9NZP1Mxxkcud3HcaxvS7I1gxoM9MSjbpenKgkti8TPCc7nQBUk9y6xXYWlhysjgAi9YjExUIxO2ozYZuwyksOvIxS4NZs2aBctyR74N3XjOO/t8GByAz2u7KR5vYJu418Y9apAuYB1n6ZZ6aE1NrjIK9mjGCKSqE3YxN5SNkKXf1zRwTUjq8cE73F7cK7DBXNFWBTZSYkLLnFg/QuqKh0dfwGgLseeKhHUxw2KiP9qH4kvXBn2UdeI8jkFMbPERiSf2KMrGKyMCtz3jL+YVRYkB4BB0hx15Brrgo/zhePXHbT692VxKF98MIMQc/v+dc6aewQZldjuq6ANrp4RM+LdjlTPg7ow==",
                "MD5OfBody": "13c0c73bbf11056450c43bf3159b3585",
                "Body": '{"foo": "bared"}',
                "Attributes": {"SenderId": "000000000000", "SentTimestamp": "1652963711"},
                "MD5OfMessageAttributes": "fca026605781cb4126a1e9044df24232",
                "MessageAttributes": {
                    "Hello": {"StringValue": "There", "DataType": "String"},
                    "General": {"StringValue": "Kenobi", "DataType": "String"},
                },
            }
        ]
    }
    _botocore_serializer_integration_test("sqs", "ReceiveMessage", response)


def test_query_serializer_sqs_none_value_in_map():
    response = {
        "Messages": [
            {
                "MessageId": "ac9baa5c-13b1-4206-aa28-2ac45ae168af",
                "ReceiptHandle": "AQEBZ14sCjWJuot0T8G2Eg3S8C+sJGg+QRKYCJjfd8iiOsrPfUzbXSjlQquT9NZP1Mxxkcud3HcaxvS7I1gxoM9MSjbpenKgkti8TPCc7nQBUk9y6xXYWlhysjgAi9YjExUIxO2ozYZuwyksOvIxS4NZs2aBctyR74N3XjOO/t8GByAz2u7KR5vYJu418Y9apAuYB1n6ZZ6aE1NrjIK9mjGCKSqE3YxN5SNkKXf1zRwTUjq8cE73F7cK7DBXNFWBTZSYkLLnFg/QuqKh0dfwGgLseeKhHUxw2KiP9qH4kvXBn2UdeI8jkFMbPERiSf2KMrGKyMCtz3jL+YVRYkB4BB0hx15Brrgo/zhePXHbT692VxKF98MIMQc/v+dc6aewQZldjuq6ANrp4RM+LdjlTPg7ow==",
                "Attributes": None,
                "MD5OfBody": "13c0c73bbf11056450c43bf3159b3585",
                "Body": '{"foo": "bared"}',
            }
        ]
    }
    expected_response = copy.deepcopy(response)
    del expected_response["Messages"][0]["Attributes"]
    _botocore_serializer_integration_test("sqs", "ReceiveMessage", response, 200, expected_response)


def test_query_protocol_error_serialization():
    exception = InvalidMessageContents("Exception message!")
    _botocore_error_serializer_integration_test(
        "sqs-query", "SendMessage", exception, "InvalidMessageContents", 400, "Exception message!"
    )


def test_query_protocol_error_serialization_plain():
    exception = ReceiptHandleIsInvalid(
        'The input receipt handle "garbage" is not a valid receipt handle.'
    )

    # Load the SQS service
    service = load_service("sqs-query")

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("ChangeMessageVisibility"), None, long_uid()
    )
    serialized_response_dict = serialized_response.to_readonly_response_dict()
    # Replace the random request ID with a static value for comparison
    serialized_response_body = re.sub(
        "<RequestId>.*</RequestId>",
        "<RequestId>static_request_id</RequestId>",
        to_str(serialized_response_dict["body"]),
    )

    # This expected_response_body differs from the actual response in the following ways:
    # - The original response does not define an encoding.
    # - There is no newline after the XML declaration.
    # - The response does not contain a Type nor Detail tag (since they aren't contained in the spec).
    # - The original response uses double quotes for the xml declaration.
    # Most of these differences should be handled equally by parsing clients, however, we might adopt some of these
    # changes in the future.
    expected_response_body = (
        "<?xml version='1.0' encoding='utf-8'?>\n"
        '<ErrorResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">'
        "<Error>"
        "<Code>ReceiptHandleIsInvalid</Code>"
        "<Message>The input receipt handle &quot;garbage&quot; is not a valid receipt handle."
        "</Message>"
        "</Error>"
        "<RequestId>static_request_id</RequestId>"
        "</ErrorResponse>"
    )

    assert serialized_response_body == expected_response_body
    assert serialized_response_dict["headers"].get("Content-Type") is not None
    assert serialized_response_dict["headers"]["Content-Type"] == "text/xml"


def test_query_protocol_custom_error_serialization():
    exception = CommonServiceException("InvalidParameterValue", "Parameter x was invalid!")
    _botocore_error_serializer_integration_test(
        "sqs-query",
        "SendMessage",
        exception,
        "InvalidParameterValue",
        400,
        "Parameter x was invalid!",
    )


def test_query_protocol_error_serialization_sender_fault():
    exception = UnsupportedOperation("Operation not supported.")
    _botocore_error_serializer_integration_test(
        "sqs-query",
        "SendMessage",
        exception,
        "AWS.SimpleQueueService.UnsupportedOperation",
        400,
        "Operation not supported.",
        True,
    )


def test_sqs_json_protocol_error_serialization_sender_fault():
    exception = UnsupportedOperation("Operation not supported.")
    _botocore_error_serializer_integration_test(
        "sqs",
        "SendMessage",
        exception,
        "AWS.SimpleQueueService.UnsupportedOperation",
        400,
        "Operation not supported.",
        True,
    )


def test_restxml_protocol_error_serialization_not_specified_for_operation():
    """
    Tests if the serializer can serialize an error which is not explicitly defined as an error shape for the
    specific operation.
    This can happen if the specification is not specific enough (f.e. S3's GetBucketAcl does not define the NoSuchBucket
    error, even though it obviously can be raised).
    """

    class NoSuchBucket(ServiceException):
        code: str = "NoSuchBucket"
        sender_fault: bool = False
        status_code: int = 400

    exception = NoSuchBucket("Exception message!")
    _botocore_error_serializer_integration_test(
        "s3",
        "GetBucketAcl",
        exception,
        "NoSuchBucket",
        400,
        "Exception message!",
    )


def test_restxml_protocol_error_serialization():
    class CloudFrontOriginAccessIdentityAlreadyExists(ServiceException):
        code: str = "CloudFrontOriginAccessIdentityAlreadyExists"
        sender_fault: bool = False
        status_code: int = 409

    exception = CloudFrontOriginAccessIdentityAlreadyExists("Exception message!")
    _botocore_error_serializer_integration_test(
        "cloudfront",
        "CreateCloudFrontOriginAccessIdentity",
        exception,
        "CloudFrontOriginAccessIdentityAlreadyExists",
        409,
        "Exception message!",
    )


def test_restxml_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "APIAccessCensorship",
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        status_code=451,
    )
    _botocore_error_serializer_integration_test(
        "cloudfront",
        "CreateCloudFrontOriginAccessIdentity",
        exception,
        "APIAccessCensorship",
        451,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
    )


def test_s3_xml_protocol_custom_error_serialization_headers():
    class NoSuchKey(ServiceException):
        code: str = "NoSuchKey"
        sender_fault: bool = False
        status_code: int = 404
        DeleteMarker: Optional[bool]
        VersionId: Optional[str]

    exception = NoSuchKey(
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        DeleteMarker=True,
        VersionId="version-id",
    )

    response = _botocore_error_serializer_integration_test(
        "s3",
        "GetObject",
        exception,
        "NoSuchKey",
        404,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
    )
    assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-delete-marker"] == "true"
    assert response["ResponseMetadata"]["HTTPHeaders"]["x-amz-version-id"] == "version-id"


def test_json_protocol_error_serialization():
    class UserPoolTaggingException(ServiceException):
        code: str = "UserPoolTaggingException"
        sender_fault: bool = False
        status_code: int = 400

    exception = UserPoolTaggingException("Exception message!")
    response = _botocore_error_serializer_integration_test(
        "cognito-idp",
        "CreateUserPool",
        exception,
        "UserPoolTaggingException",
        400,
        "Exception message!",
    )

    # some clients also expect the X-Amzn-Errortype header according to
    # https://awslabs.github.io/smithy/1.0/spec/aws/aws-json-1_1-protocol.html#operation-error-serialization
    assert (
        response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amzn-errortype")
        == "UserPoolTaggingException"
    )


def test_json_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "APIAccessCensorship",
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        status_code=451,
    )
    response = _botocore_error_serializer_integration_test(
        "cognito-idp",
        "CreateUserPool",
        exception,
        "APIAccessCensorship",
        451,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
    )

    # some clients also expect the X-Amzn-Errortype header according to
    # https://awslabs.github.io/smithy/1.0/spec/aws/aws-json-1_1-protocol.html#operation-error-serialization
    assert (
        response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amzn-errortype")
        == "APIAccessCensorship"
    )


def test_json_protocol_error_serialization_with_additional_members():
    exception = TransactionCanceledException("Exception message!")
    cancellation_reasons = [
        CancellationReason(
            Code="TestCancellationReasonCode",
            Message="TestCancellationReasonMessage",
            Item={"TestAttributeName": AttributeValue(S="TestAttributeValue")},
        )
    ]
    exception.CancellationReasons = cancellation_reasons
    _botocore_error_serializer_integration_test(
        "dynamodb",
        "ExecuteTransaction",
        exception,
        "TransactionCanceledException",
        400,
        "Exception message!",
        CancellationReasons=cancellation_reasons,
        Message="Exception message!",
    )


def test_json_protocol_error_serialization_with_shaped_default_members_on_root():
    exception = TransactionCanceledException("Exception message!")
    service = load_service("dynamodb")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("ExecuteTransaction"), None, long_uid()
    )
    body = serialized_response.data
    parsed_body = json.loads(body)
    # assert Message with first character in upper-case as specified in the specs
    assert "Message" in parsed_body
    assert "message" not in parsed_body


def test_rest_json_protocol_error_serialization_with_additional_members():
    class NotFoundException(ServiceException):
        code: str = "NotFoundException"
        sender_fault: bool = False
        status_code: int = 404
        ResourceType: str

    exception = NotFoundException("Exception message!")
    resource_type = "Resource Type Exception Message Body"
    exception.ResourceType = resource_type
    _botocore_error_serializer_integration_test(
        "apigatewayv2",
        "CreateApi",
        exception,
        "NotFoundException",
        404,
        "Exception message!",
        ResourceType=resource_type,
        Message="Exception message!",
    )


def test_rest_json_protocol_error_serialization_with_shaped_default_members_on_root():
    exception = ResourceNotFoundException("Exception message!")
    exception.Type = "User"
    service = load_service("lambda")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("GetLayerVersion"), None, long_uid()
    )
    body = serialized_response.data
    parsed_body = json.loads(body)
    # assert Message and Type with first character in upper-case as specified in the specs
    assert "Message" in parsed_body
    assert "message" not in parsed_body
    assert "Type" in parsed_body
    assert parsed_body["Type"] == "User"
    assert "type" not in parsed_body


def test_query_protocol_error_serialization_with_additional_members():
    exception = VerificationException("Exception message!")
    status = "Status Exception Message Body"
    exception.Status = status
    _botocore_error_serializer_integration_test(
        "sns",
        "VerifySMSSandboxPhoneNumber",
        exception,
        "VerificationException",
        400,
        "Exception message!",
        Status=status,
        Message="Exception message!",
    )


def test_query_protocol_error_serialization_with_default_members_not_on_root():
    exception = VerificationException("Exception message!")
    status = "Status Exception Message Body"
    exception.Status = status
    service = load_service("sns")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("VerifySMSSandboxPhoneNumber"), None, long_uid()
    )
    body = serialized_response.data
    parser = ElementTree.XMLParser(target=ElementTree.TreeBuilder())
    parser.feed(body)
    root = parser.close()
    # The root tag contains a possible namespace, f.e. {http://ec2.amazonaws.com/doc/2016-11-15}Response.
    assert len([child for child in root if "Message" in child.tag]) == 0


def test_rest_xml_protocol_error_serialization_with_default_members_not_on_root():
    exception = NoSuchHostedZone("Exception message!")
    service = load_service("route53")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("DeleteHostedZone"), None, long_uid()
    )
    body = serialized_response.data
    parser = ElementTree.XMLParser(target=ElementTree.TreeBuilder())
    parser.feed(body)
    root = parser.close()
    # The root tag contains a possible namespace, f.e. {http://ec2.amazonaws.com/doc/2016-11-15}Response.
    assert len([child for child in root if "Message" in child.tag]) == 0


def test_rest_xml_protocol_error_serialization_with_additional_members():
    class InvalidObjectState(ServiceException):
        code: str = "InvalidObjectState"
        sender_fault: bool = False
        status_code: int = 400
        StorageClass: str
        AccessTier: str

    exception = InvalidObjectState("Exception message!")
    exception.AccessTier = "ARCHIVE_ACCESS"
    exception.StorageClass = "STANDARD"
    _botocore_error_serializer_integration_test(
        "s3",
        "GetObject",
        exception,
        "InvalidObjectState",
        400,
        "Exception message!",
        AccessTier="ARCHIVE_ACCESS",
        StorageClass="STANDARD",
    )


def test_json_protocol_content_type_1_0():
    """AppRunner defines the jsonVersion 1.0, therefore the Content-Type needs to be application/x-amz-json-1.0."""
    service = load_service("apprunner")
    response_serializer = create_serializer(service)
    result: Response = response_serializer.serialize_to_response(
        {}, service.operation_model("DeleteConnection"), None, long_uid()
    )
    assert result is not None
    assert result.content_type is not None
    assert result.content_type == "application/x-amz-json-1.0"


def test_json_protocol_content_type_1_1():
    """Logs defines the jsonVersion 1.1, therefore the Content-Type needs to be application/x-amz-json-1.1."""
    service = load_service("logs")
    response_serializer = create_serializer(service)
    result: Response = response_serializer.serialize_to_response(
        {}, service.operation_model("DeleteLogGroup"), None, long_uid()
    )
    assert result is not None
    assert result.content_type is not None
    assert result.content_type == "application/x-amz-json-1.1"


def test_json_serializer_cognito_with_botocore():
    parameters = {
        "UserPool": {
            "Id": "string",
            "Name": "string",
            "Policies": {
                "PasswordPolicy": {
                    "MinimumLength": 123,
                    "RequireUppercase": True,
                    "RequireLowercase": True,
                    "RequireNumbers": True,
                    "RequireSymbols": True,
                    "TemporaryPasswordValidityDays": 123,
                }
            },
            "LambdaConfig": {
                "PreSignUp": "string",
                "CustomMessage": "string",
                "PostConfirmation": "string",
                "PreAuthentication": "string",
                "PostAuthentication": "string",
                "DefineAuthChallenge": "string",
                "CreateAuthChallenge": "string",
                "VerifyAuthChallengeResponse": "string",
                "PreTokenGeneration": "string",
                "UserMigration": "string",
                "CustomSMSSender": {"LambdaVersion": "V1_0", "LambdaArn": "string"},
                "CustomEmailSender": {"LambdaVersion": "V1_0", "LambdaArn": "string"},
                "KMSKeyID": "string",
            },
            "Status": "Enabled",
            "LastModifiedDate": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
            "CreationDate": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
            "SchemaAttributes": [
                {
                    "Name": "string",
                    "AttributeDataType": "String",
                    "DeveloperOnlyAttribute": True,
                    "Mutable": True,
                    "Required": True,
                    "NumberAttributeConstraints": {"MinValue": "string", "MaxValue": "string"},
                    "StringAttributeConstraints": {"MinLength": "string", "MaxLength": "string"},
                },
            ],
            "AutoVerifiedAttributes": [
                "phone_number",
            ],
            "AliasAttributes": [
                "phone_number",
            ],
            "UsernameAttributes": [
                "phone_number",
            ],
            "SmsVerificationMessage": "string",
            "EmailVerificationMessage": "string",
            "EmailVerificationSubject": "string",
            "VerificationMessageTemplate": {
                "SmsMessage": "string",
                "EmailMessage": "string",
                "EmailSubject": "string",
                "EmailMessageByLink": "string",
                "EmailSubjectByLink": "string",
                "DefaultEmailOption": "CONFIRM_WITH_LINK",
            },
            "SmsAuthenticationMessage": "string",
            "MfaConfiguration": "OFF",
            "DeviceConfiguration": {
                "ChallengeRequiredOnNewDevice": True,
                "DeviceOnlyRememberedOnUserPrompt": True,
            },
            "EstimatedNumberOfUsers": 123,
            "EmailConfiguration": {
                "SourceArn": "string",
                "ReplyToEmailAddress": "string",
                "EmailSendingAccount": "COGNITO_DEFAULT",
                "From": "string",
                "ConfigurationSet": "string",
            },
            "SmsConfiguration": {"SnsCallerArn": "string", "ExternalId": "string"},
            "UserPoolTags": {"string": "string"},
            "SmsConfigurationFailure": "string",
            "EmailConfigurationFailure": "string",
            "Domain": "string",
            "CustomDomain": "string",
            "AdminCreateUserConfig": {
                "AllowAdminCreateUserOnly": True,
                "UnusedAccountValidityDays": 123,
                "InviteMessageTemplate": {
                    "SMSMessage": "string",
                    "EmailMessage": "string",
                    "EmailSubject": "string",
                },
            },
            "UserPoolAddOns": {"AdvancedSecurityMode": "OFF"},
            "UsernameConfiguration": {"CaseSensitive": True},
            "Arn": "string",
            "AccountRecoverySetting": {
                "RecoveryMechanisms": [
                    {"Priority": 123, "Name": "verified_email"},
                ]
            },
        }
    }
    _botocore_serializer_integration_test("cognito-idp", "DescribeUserPool", parameters)


def test_json_serializer_date_serialization_with_botocore():
    parameters = {
        "UserPool": {
            "LastModifiedDate": datetime(2022, 2, 8, 9, 17, 40, 122939, tzinfo=tzlocal()),
        }
    }
    _botocore_serializer_integration_test("cognito-idp", "DescribeUserPool", parameters)


def test_restjson_protocol_error_serialization():
    class ThrottledException(ServiceException):
        code: str = "ThrottledException"
        sender_fault: bool = False
        status_code: int = 429

    exception = ThrottledException("Exception message!")
    response = _botocore_error_serializer_integration_test(
        "xray",
        "UpdateSamplingRule",
        exception,
        "ThrottledException",
        429,
        "Exception message!",
    )

    # some clients also expect the X-Amzn-Errortype header according to
    # https://awslabs.github.io/smithy/1.0/spec/aws/aws-restjson1-protocol.html#operation-error-serialization
    assert (
        response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amzn-errortype")
        == "ThrottledException"
    )


def test_restjson_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "APIAccessCensorship",
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        status_code=451,
    )
    response = _botocore_error_serializer_integration_test(
        "xray",
        "UpdateSamplingRule",
        exception,
        "APIAccessCensorship",
        451,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
    )

    # some clients also expect the X-Amzn-Errortype header according to
    # https://awslabs.github.io/smithy/1.0/spec/aws/aws-restjson1-protocol.html#operation-error-serialization
    assert (
        response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amzn-errortype")
        == "APIAccessCensorship"
    )


def test_restjson_serializer_xray_with_botocore():
    parameters = {
        "SamplingRuleRecord": {
            "SamplingRule": {
                "RuleName": "string",
                "RuleARN": "123456789001234567890",
                "ResourceARN": "123456789001234567890",
                "Priority": 123,
                "FixedRate": 123.0,
                "ReservoirSize": 123,
                "ServiceName": "string",
                "ServiceType": "string",
                "Host": "string",
                "HTTPMethod": "string",
                "URLPath": "string",
                "Version": 123,
                "Attributes": {"string": "string"},
            },
            "CreatedAt": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
            "ModifiedAt": datetime(2015, 1, 1, 23, 59, 59, 1000, tzinfo=tzutc()),
        }
    }

    _botocore_serializer_integration_test("xray", "UpdateSamplingRule", parameters)


def test_restjson_header_target_serialization():
    """
    Tests the serialization of attributes into a specified header key based on this example from glacier:

        "InitiateJobOutput":{
          "type":"structure",
          "members":{
            "location":{
              "shape":"string",
              "location":"header",
              "locationName":"Location"
            },
            "jobId":{
              "shape":"string",
              "location":"header",
              "locationName":"x-amz-job-id"
            },
            "jobOutputPath":{
              "shape":"string",
              "location":"header",
              "locationName":"x-amz-job-output-path"
            }
          },
          "documentation":"<p>Contains the Amazon S3 Glacier response to your request.</p>"
        },
    """
    response = {
        "location": "/here",
        "jobId": "42069",
        "jobOutputPath": "/there",
    }

    result = _botocore_serializer_integration_test(
        "glacier",
        "InitiateJob",
        response,
        status_code=202,
    )

    headers = result["ResponseMetadata"]["HTTPHeaders"]
    assert "location" in headers
    assert "x-amz-job-id" in headers
    assert "x-amz-job-output-path" in headers
    assert "locationName" not in headers
    assert "jobOutputPath" not in headers

    assert headers["location"] == "/here"
    assert headers["x-amz-job-id"] == "42069"
    assert headers["x-amz-job-output-path"] == "/there"


def test_restjson_headers_target_serialization():
    # SendApiAssetResponse
    response = {
        "Body": "hello",
        "ResponseHeaders": {
            "foo": "bar",
            "baz": "ed",
        },
    }

    # skipping assert here, because the response will contain all HTTP headers (given the nature of "ResponseHeaders"
    # attribute).
    result = _botocore_serializer_integration_test(
        "dataexchange", "SendApiAsset", response, expected_response_content=_skip_assert
    )

    assert result["Body"] == "hello"
    assert result["ResponseHeaders"]["foo"] == "bar"
    assert result["ResponseHeaders"]["baz"] == "ed"

    headers = result["ResponseMetadata"]["HTTPHeaders"]
    assert "foo" in headers
    assert "baz" in headers
    assert headers["foo"] == "bar"
    assert headers["baz"] == "ed"


def test_restjson_statuscode_target_serialization():
    _botocore_serializer_integration_test(
        "lambda",
        "Invoke",
        {
            "StatusCode": 203,
            "LogResult": "Log Message!",
            "ExecutedVersion": "Latest",
            "Payload": "test payload",
        },
        status_code=203,
    )


def test_restjson_payload_serialization():
    """
    Tests the serialization of specific member attributes as payload, based on an appconfig example:

        "Configuration":{
          "type":"structure",
          "members":{
            "Content":{
              "shape":"Blob",
            },
            "ConfigurationVersion":{
              "shape":"Version",
              "location":"header",
              "locationName":"Configuration-Version"
            },
            "ContentType":{
              "shape":"String",
              "location":"header",
              "locationName":"Content-Type"
            }
          },
          "payload":"Content"
        },
    """

    response = {
        "Content": '{"foo": "bar"}',
        "ConfigurationVersion": "123",
        "ContentType": "application/json",
    }

    result = _botocore_serializer_integration_test(
        "appconfig",
        "GetConfiguration",
        response,
        status_code=200,
    )
    headers = result["ResponseMetadata"]["HTTPHeaders"]
    assert "configuration-version" in headers
    assert headers["configuration-version"] == "123"
    assert headers["content-type"] == "application/json"


def test_restjson_none_serialization():
    parameters = {
        "FunctionName": "test-name",
        "VpcConfig": {"SubnetIds": None, "SecurityGroupIds": [None], "VpcId": "123"},
        "TracingConfig": None,
        "DeadLetterConfig": {},
    }
    expected = {
        "FunctionName": "test-name",
        "VpcConfig": {"SecurityGroupIds": [], "VpcId": "123"},
        "DeadLetterConfig": {},
    }
    _botocore_serializer_integration_test(
        "lambda", "CreateFunction", parameters, status_code=201, expected_response_content=expected
    )
    exception = CommonServiceException("CodeVerificationFailedException", None)
    _botocore_error_serializer_integration_test(
        "lambda",
        "CreateFunction",
        exception,
        "CodeVerificationFailedException",
        400,
        "",
    )


def test_restxml_none_serialization():
    # Structure = None
    _botocore_serializer_integration_test(
        "route53", "ListHostedZonesByName", {}, expected_response_content={}
    )
    # Structure Value = None
    parameters = {"HostedZones": None}
    _botocore_serializer_integration_test(
        "route53", "ListHostedZonesByName", parameters, expected_response_content={}
    )
    # List Value = None
    parameters = {"HostedZones": [None]}
    expected = {"HostedZones": []}
    _botocore_serializer_integration_test(
        "route53", "ListHostedZonesByName", parameters, expected_response_content=expected
    )
    # Exception without a message
    exception = CommonServiceException("NoSuchKeySigningKey", None)
    _botocore_error_serializer_integration_test(
        "route53",
        "DeleteKeySigningKey",
        exception,
        "NoSuchKeySigningKey",
        400,
        "",
    )


def test_restjson_int_header_serialization():
    response = {
        "Configuration": '{"foo": "bar"}',
        "ContentType": "application/json",
        "NextPollConfigurationToken": "abcdefg",
        "NextPollIntervalInSeconds": 42,
    }
    _botocore_serializer_integration_test("appconfigdata", "GetLatestConfiguration", response)


def test_ec2_serializer_ec2_with_botocore():
    parameters = {
        "InstanceEventWindow": {
            "InstanceEventWindowId": "string",
            "TimeRanges": [
                {
                    "StartWeekDay": "sunday",
                    "StartHour": 123,
                    "EndWeekDay": "sunday",
                    "EndHour": 123,
                },
            ],
            "Name": "string",
            "CronExpression": "string",
            "AssociationTarget": {
                "InstanceIds": [
                    "string",
                ],
                "Tags": [
                    {"Key": "string", "Value": "string"},
                ],
                "DedicatedHostIds": [
                    "string",
                ],
            },
            "State": "creating",
            "Tags": [
                {"Key": "string", "Value": "string"},
            ],
        }
    }

    _botocore_serializer_integration_test("ec2", "CreateInstanceEventWindow", parameters)


def test_ec2_serializer_ec2_with_empty_response():
    _botocore_serializer_integration_test("ec2", "CreateTags", {})


def test_ec2_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "IdempotentParameterMismatch", "Different payload, same token?!"
    )
    _botocore_error_serializer_integration_test(
        "ec2",
        "StartInstances",
        exception,
        "IdempotentParameterMismatch",
        400,
        "Different payload, same token?!",
    )


def test_ec2_protocol_errors_have_response_root_element():
    exception = CommonServiceException(
        "InvalidSubnetID.NotFound", "The subnet ID 'vpc-test' does not exist"
    )
    service = load_service("ec2")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("DescribeSubnets"), None, long_uid()
    )
    body = serialized_response.data
    parser = ElementTree.XMLParser(target=ElementTree.TreeBuilder())
    parser.feed(body)
    root = parser.close()
    # The root tag contains a possible namespace, f.e. {http://ec2.amazonaws.com/doc/2016-11-15}Response.
    assert re.sub(r"^{.*}", "", root.tag) == "Response"


def test_restxml_s3_errors_have_error_root_element():
    exception = CommonServiceException("NoSuchBucket", "The specified bucket does not exist")
    service = load_service("s3")
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("GetObject"), None, long_uid()
    )
    body = serialized_response.data
    parser = ElementTree.XMLParser(target=ElementTree.TreeBuilder())
    parser.feed(body)
    root = parser.close()
    assert root.tag == "Error"


def test_restxml_without_output_shape():
    _botocore_serializer_integration_test("cloudfront", "DeleteDistribution", {}, status_code=204)


def test_restxml_header_location():
    """Tests fields with the location trait "header" for rest-xml."""
    _botocore_serializer_integration_test(
        "cloudfront",
        "CreateCloudFrontOriginAccessIdentity",
        {
            "Location": "location-header-field",
            "ETag": "location-etag-field",
            "CloudFrontOriginAccessIdentity": {},
        },
        status_code=201,
    )
    # Test a boolean header location field
    parameters = {
        "ContentLength": 0,
        "Body": "",
        "DeleteMarker": True,
        "ContentType": "string",
        "Metadata": {"string": "string"},
        "StatusCode": 200,
    }
    _botocore_serializer_integration_test("s3", "GetObject", parameters)


def test_restxml_headers_location():
    """Tests fields with the location trait "headers" for rest-xml."""
    _botocore_serializer_integration_test(
        "s3",
        "HeadObject",
        {
            "DeleteMarker": False,
            "Metadata": {"headers_key1": "headers_value1", "headers_key2": "headers_value2"},
            "ContentType": "application/octet-stream",
            # The content length should explicitly be tested here.
            "ContentLength": 159,
            "StatusCode": 200,
        },
    )


def test_restjson_header_location():
    """Tests fields with the location trait "header" for rest-xml."""
    _botocore_serializer_integration_test(
        "ebs", "GetSnapshotBlock", {"BlockData": "binary-data", "DataLength": 15}
    )


def test_restjson_headers_location():
    """Tests fields with the location trait "headers" for rest-json."""
    response = _botocore_serializer_integration_test(
        "dataexchange",
        "SendApiAsset",
        {
            "ResponseHeaders": {"headers_key1": "headers_value1", "headers_key2": "headers_value2"},
        },
        expected_response_content=_skip_assert,
    )
    # The spec does not define a locationName for ResponseHeaders, which means there is no header field prefix.
    # Therefore, _all_ header fields are parsed by botocore (which is technically correct).
    # We only check if the two header fields are present.
    assert "ResponseHeaders" in response
    assert "headers_key1" in response["ResponseHeaders"]
    assert "headers_key2" in response["ResponseHeaders"]
    assert "headers_value1" == response["ResponseHeaders"]["headers_key1"]
    assert "headers_value2" == response["ResponseHeaders"]["headers_key2"]


def _iterable_to_stream(iterable, buffer_size=io.DEFAULT_BUFFER_SIZE):
    """
    Concerts a given iterable (generator) to a stream for testing purposes.
    This wrapper does not "real streaming". The event serializer will wait for the end of the stream / generator.
    """

    class IterStream(io.RawIOBase):
        def __init__(self):
            self.leftover = None

        def readable(self):
            return True

        def readinto(self, b):
            try:
                chunk = next(iterable)
                b[: len(chunk)] = chunk
                return len(chunk)
            except StopIteration:
                return 0

    return io.BufferedReader(IterStream(), buffer_size=buffer_size)


def test_json_event_streaming():
    # Create test events from Kinesis' SubscribeToShard operation
    event_1 = {
        "SubscribeToShardEvent": {
            "Records": [
                {
                    "SequenceNumber": "1",
                    "Data": b"event_data_1_record_1",
                    "PartitionKey": "event_1_partition_key_record_1",
                },
                {
                    "SequenceNumber": "2",
                    "Data": b"event_data_1_record_2",
                    "PartitionKey": "event_1_partition_key_record_1",
                },
            ],
            "ContinuationSequenceNumber": "1",
            "MillisBehindLatest": 1337,
        }
    }
    event_2 = {
        "SubscribeToShardEvent": {
            "Records": [
                {
                    "SequenceNumber": "3",
                    "Data": b"event_data_2_record_1",
                    "PartitionKey": "event_2_partition_key_record_1",
                },
                {
                    "SequenceNumber": "4",
                    "Data": b"event_data_2_record_2",
                    "PartitionKey": "event_2_partition_key_record_2",
                },
            ],
            "ContinuationSequenceNumber": "2",
            "MillisBehindLatest": 1338,
        }
    }

    # Create the response which contains the generator
    def event_generator() -> Iterator:
        yield event_1
        yield event_2

    response = {"EventStream": event_generator()}
    _botocore_event_streaming_test(
        "kinesis", "SubscribeToShard", response, "EventStream", [event_1, event_2]
    )


def test_s3_event_streaming():
    event_1 = {"Records": {"Payload": b"Streamed-Body-Content"}}
    event_2 = {"End": {}}

    # Create the response which contains the generator
    def event_generator() -> Iterator:
        yield event_1
        yield event_2

    response = {"Payload": event_generator()}
    _botocore_event_streaming_test(
        "s3", "SelectObjectContent", response, "Payload", [event_1, event_2]
    )


def test_all_non_existing_key():
    """Tests the different protocols to allow non-existing keys in structures / dicts."""
    # query
    _botocore_serializer_integration_test(
        "cloudformation",
        "DetectStackResourceDrift",
        {
            "StackResourceDrift": {
                "StackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/MyStack/d0a825a0-e4cd-xmpl-b9fb-061c69e99204",
                "unknown": {"foo": "bar"},
            }
        },
        expected_response_content={
            "StackResourceDrift": {
                "StackId": "arn:aws:cloudformation:us-west-2:123456789012:stack/MyStack/d0a825a0-e4cd-xmpl-b9fb-061c69e99204",
            }
        },
    )
    # ec2
    _botocore_serializer_integration_test(
        "ec2",
        "CreateInstanceEventWindow",
        {
            "InstanceEventWindow": {
                "InstanceEventWindowId": "string",
                "unknown": {"foo": "bar"},
            },
            "unknown": {"foo": "bar"},
        },
        expected_response_content={
            "InstanceEventWindow": {
                "InstanceEventWindowId": "string",
            }
        },
    )
    # json
    _botocore_serializer_integration_test(
        "cognito-idp",
        "DescribeUserPool",
        {
            "UserPool": {
                "Id": "string",
                "Unknown": "Ignored",
            }
        },
        expected_response_content={
            "UserPool": {
                "Id": "string",
            }
        },
    )
    # rest-json
    _botocore_serializer_integration_test(
        "xray",
        "UpdateSamplingRule",
        {
            "SamplingRuleRecord": {
                "SamplingRule": {
                    "ResourceARN": "123456789001234567890",
                    "Unknown": "Ignored",
                },
            }
        },
        expected_response_content={
            "SamplingRuleRecord": {
                "SamplingRule": {
                    "ResourceARN": "123456789001234567890",
                },
            }
        },
    )
    # rest-xml
    _botocore_serializer_integration_test(
        "cloudfront",
        "TestFunction",
        {
            "TestResult": {
                "FunctionErrorMessage": "string",
            },
            "Unknown": "Ignored",
        },
        expected_response_content={
            "TestResult": {
                "FunctionErrorMessage": "string",
            },
        },
    )


def test_no_mutation_of_parameters():
    service = load_service("appconfig")
    response_serializer = create_serializer(service)

    parameters = {
        "ApplicationId": "app_id",
        "ConfigurationProfileId": "conf_id",
        "VersionNumber": 1,
        "Content": b'{"Id":"foo"}',
        "ContentType": "application/json",
    }
    expected = parameters.copy()

    # serialize response and check whether parameters are unchanged
    _ = response_serializer.serialize_to_response(
        parameters, service.operation_model("CreateHostedConfigurationVersion"), None, long_uid()
    )
    assert parameters == expected


def test_serializer_error_on_protocol_error_invalid_exception():
    """Test that the serializer raises a ProtocolSerializerError in case of invalid exception to serialize."""
    service = load_service("sqs")
    operation_model = service.operation_model("SendMessage")
    serializer = QueryResponseSerializer()
    with pytest.raises(ProtocolSerializerError):
        # a known protocol error would be if we try to serialize an exception which is not a CommonServiceException and
        # also not a generated exception
        serializer.serialize_error_to_response(
            NotImplementedError(), operation_model, None, long_uid()
        )


def test_serializer_error_on_protocol_error_invalid_data():
    """Test that the serializer raises a ProtocolSerializerError in case of invalid data to serialize."""
    service = load_service("dynamodbstreams")
    operation_model = service.operation_model("DescribeStream")
    serializer = QueryResponseSerializer()
    with pytest.raises(ProtocolSerializerError):
        serializer.serialize_to_response(
            {"StreamDescription": {"CreationRequestDateTime": "invalid_timestamp"}},
            operation_model,
            None,
            long_uid(),
        )


def test_serializer_error_on_unknown_error():
    """Test that the serializer raises a UnknownSerializerError in case of an unknown exception."""
    service = load_service("sqs")
    operation_model = service.operation_model("SendMessage")
    serializer = QueryResponseSerializer()

    # An unknown error is obviously hard to trigger (because we would fix it if we would know of a way to trigger it),
    # therefore we patch a function to raise an unexpected error
    def raise_error(*args, **kwargs):
        raise NotImplementedError()

    serializer._serialize_response = raise_error
    with pytest.raises(UnknownSerializerError):
        serializer.serialize_to_response({}, operation_model, None, long_uid())


class ComparableBytesIO(BytesIO):
    """
    BytesIO object that's treated like a value object when comparing it to other streams.
    """

    def __eq__(self, other):
        if hasattr(other, "read"):
            return other.read() == self.read()

        if isinstance(other, ResponseStream):
            return other.response.data == self.read()

        return super(ComparableBytesIO, self).__eq__(other)


class ComparableBytesList(list):
    """
    Makes a list of bytes comparable to strings.
    """

    def __eq__(self, other):
        if isinstance(other, str):
            return b"".join(self) == other.encode("utf-8")

        return super(ComparableBytesList, self).__eq__(other)


class ComparableBytesIterator(Iterator[bytes]):
    def __init__(self, bytes_list: List[bytes]):
        self.gen = iter(bytes_list)
        self.value = b"".join(bytes_list)

    def __next__(self) -> bytes:
        return next(self.gen)

    def __iter__(self) -> Iterator[bytes]:
        return self.gen

    def __eq__(self, other):
        if hasattr(other, "read"):
            return other.read() == self.value

        if isinstance(other, ResponseStream):
            return other.response.data == self.value

        return super(ComparableBytesIterator, self).__eq__(other)


@pytest.mark.parametrize(
    "payload",
    [
        "<foo-bar/>",
        ComparableBytesList([b"<", b"foo-bar", b"/>"]),
        ComparableBytesIO(b"<foo-bar/>"),
        ComparableBytesIterator([b"<", b"foo-bar", b"/>"]),
    ],
    ids=["Literal", "List[byte]", "IO[byte]", "Iterator[byte]"],
)
def test_restxml_streaming_payload(payload):
    """Tests an operation where the payload can be streaming for rest-xml. We're testing four cases,
    two non-streaming and two streaming: a literal, a list (that's treated specially by werkzeug), a file-like
    ``IO[bytes]`` object, and an iterator. Since the _botocore_serializer_integration_test does equality checks on
    parameters, and we're receiving different objects for streams, we wrap the payloads in custom classes that can be
    compared to strings."""
    parameters = {
        "ContentLength": 10,
        "Body": payload,
        "ContentType": "text/xml",
        "Metadata": {},
        "StatusCode": 200,
    }
    _botocore_serializer_integration_test("s3", "GetObject", parameters)


@pytest.mark.parametrize(
    "payload",
    [
        '{"foo":"bar"}',
        ComparableBytesList([b"{", b'"foo"', b":", b'"bar"', b"}"]),
        ComparableBytesIO(b'{"foo":"bar"}'),
        ComparableBytesIterator([b"{", b'"foo"', b":", b'"bar"', b"}"]),
    ],
    ids=["Literal", "List[byte]", "IO[byte]", "Iterator[byte]"],
)
def test_restjson_streaming_payload(payload):
    """See docs for ``test_restxml_streaming_payload``."""
    _botocore_serializer_integration_test(
        "lambda",
        "Invoke",
        {
            "StatusCode": 200,
            "Payload": payload,
        },
    )


@pytest.mark.parametrize(
    "service,accept_header,content_type_header,expected_mime_type",
    [
        # Test default S3
        ("s3", None, None, "application/xml"),
        # Test default STS
        ("sts", None, None, "text/xml"),
        # Test STS for "any" Accept header
        ("sts", "*/*", None, "text/xml"),
        # Test STS for "any" Accept header and xml content
        ("sts", "*/*", "text/xml", "text/xml"),
        # Test STS without Accept and xml content
        ("sts", None, "text/xml", "text/xml"),
        # Test STS without Accept and JSON content
        ("sts", None, "application/json", "application/json"),
        # Test STS with JSON Accept and XML content
        ("sts", "application/json", "text/xml", "application/json"),
        # Test default Kinesis
        ("kinesis", None, None, "application/json"),
        # Test Kinesis for "any" Accept header
        ("kinesis", "*/*", None, "application/json"),
        # Test Kinesis for "any" Accept header and JSON content
        ("kinesis", "*/*", "application/json", "application/json"),
        # Test Kinesis without Accept and CBOR content
        ("kinesis", None, "application/cbor", "application/cbor"),
        # Test Kinesis without Accept and CBOR content
        ("kinesis", None, "application/cbor", "application/cbor"),
        # Test Kinesis with JSON Accept and CBOR content
        ("kinesis", "application/json", "application/cbor", "application/json"),
        # Test Kinesis with CBOR Accept and JSON content
        ("kinesis", "application/cbor", "application/json", "application/cbor"),
        # Test Kinesis with CBOR 1.1 Accept and JSON content
        ("kinesis", APPLICATION_AMZ_CBOR_1_1, "application/json", APPLICATION_AMZ_CBOR_1_1),
        # Test Kinesis with non-supported Accept header and without Content-Type
        ("kinesis", "unknown/content-type", None, "application/json"),
        # Test Kinesis with non-supported Accept header and CBOR Content-Type
        ("kinesis", "unknown/content-type", "application/cbor", "application/json"),
        # Test Kinesis with non-supported Content-Type
        ("kinesis", None, "unknown/content-type", "application/json"),
    ],
)
def test_accept_header_detection(
    service: str,
    accept_header: Optional[str],
    content_type_header: Optional[str],
    expected_mime_type: str,
):
    service_model = load_service(service)
    response_serializer = create_serializer(service_model)
    headers = Headers()
    if accept_header:
        headers["Accept"] = accept_header
    if content_type_header:
        headers["Content-Type"] = content_type_header
    mime_type = response_serializer._get_mime_type(headers)
    assert (
        mime_type == expected_mime_type
    ), f"Detected mime type ({mime_type}) was not as expected ({expected_mime_type})"


@pytest.mark.parametrize(
    "headers_dict",
    [{"Content-Type": "application/json"}, {"Accept": "application/json"}],
)
def test_query_protocol_json_serialization(headers_dict):
    service = load_service("sts")
    response_serializer = create_serializer(service)
    headers = Headers(headers_dict)
    utc_timestamp = 1661255665.123
    response_data = GetSessionTokenResponse(
        Credentials=Credentials(
            AccessKeyId="accessKeyId",
            SecretAccessKey="secretAccessKey",
            SessionToken="sessionToken",
            Expiration=datetime.utcfromtimestamp(utc_timestamp),
        )
    )
    result: Response = response_serializer.serialize_to_response(
        response_data, service.operation_model("GetSessionToken"), headers, long_uid()
    )
    assert result is not None
    assert result.content_type is not None
    assert result.content_type == "application/json"
    parsed_data = json.loads(result.data)
    # Ensure the structure is the same as for query-xml (f.e. with "SOAP"-like root element), but just JSON encoded
    assert "GetSessionTokenResponse" in parsed_data
    assert "ResponseMetadata" in parsed_data["GetSessionTokenResponse"]
    assert "GetSessionTokenResult" in parsed_data["GetSessionTokenResponse"]
    # Make sure the timestamp is formatted as str(int(utc float))
    assert parsed_data["GetSessionTokenResponse"]["GetSessionTokenResult"].get(
        "Credentials", {}
    ).get("Expiration") == str(int(utc_timestamp))


@pytest.mark.parametrize(
    "headers_dict",
    [{"Content-Type": "application/cbor"}, {"Accept": "application/cbor"}],
)
def test_json_protocol_cbor_serialization(headers_dict):
    service = load_service("kinesis")
    response_serializer = create_serializer(service)
    headers = Headers(headers_dict)
    response_data = GetRecordsOutput(
        Records=[
            Record(
                SequenceNumber="test_sequence_number",
                Data=b"test_data",
                PartitionKey="test_partition_key",
            )
        ]
    )
    result: Response = response_serializer.serialize_to_response(
        response_data, service.operation_model("GetRecords"), headers, long_uid()
    )
    assert result is not None
    assert result.content_type is not None
    assert result.content_type == "application/cbor"
    parsed_data = cbor2_loads(result.data)
    assert parsed_data == response_data


class TestAwsResponseSerializerDecorator:
    def test_query_internal_error(self):
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            raise ValueError("oh noes!")

        response = fn(Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 500
        assert b"<Code>InternalError</Code>" in response.data

    def test_query_service_error(self):
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            raise UnsupportedOperation("Operation not supported.")

        response = fn(Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 400
        assert b"<Code>AWS.SimpleQueueService.UnsupportedOperation</Code>" in response.data
        assert b"<Message>Operation not supported.</Message>" in response.data

    def test_query_valid_response(self):
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            from localstack.aws.api.sqs import ListQueuesResult

            return ListQueuesResult(
                QueueUrls=[
                    "https://localhost:4566/000000000000/my-queue-1",
                    "https://localhost:4566/000000000000/my-queue-2",
                ]
            )

        response = fn(Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 200
        assert (
            b"<QueueUrl>https://localhost:4566/000000000000/my-queue-1</QueueUrl>" in response.data
        )
        assert (
            b"<QueueUrl>https://localhost:4566/000000000000/my-queue-2</QueueUrl>" in response.data
        )

    def test_query_valid_response_content_negotiation(self):
        # this test verifies that request header values are passed correctly to perform content negotation
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            from localstack.aws.api.sqs import ListQueuesResult

            return ListQueuesResult(
                QueueUrls=[
                    "https://localhost:4566/000000000000/my-queue-1",
                    "https://localhost:4566/000000000000/my-queue-2",
                ]
            )

        response = fn(
            Request("POST", "/", body="Action=ListQueues", headers={"Accept": "application/json"})
        )
        assert response.status_code == 200
        assert response.json["ListQueuesResponse"]["ListQueuesResult"] == {
            "QueueUrl": [
                "https://localhost:4566/000000000000/my-queue-1",
                "https://localhost:4566/000000000000/my-queue-2",
            ]
        }

    def test_return_invalid_none_type_causes_internal_error(self):
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            return None

        response = fn(Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 500
        assert b"<Code>InternalError</Code>" in response.data

    def test_response_pass_through(self):
        # returning a response directly will forego the serializer
        @aws_response_serializer("sqs-query", "ListQueues")
        def fn(request: Request):
            return Response(b"ok", status=201)

        response = fn(Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 201
        assert response.data == b"ok"

    def test_invoke_using_kwargs(self):
        @aws_response_serializer("sqs", "ListQueues")
        def fn(request: Request):
            return Response(b"ok", status=201)

        response = fn(request=Request("POST", "/", body="Action=ListQueues"))
        assert response.status_code == 201
        assert response.data == b"ok"

    def test_invoke_on_bound_method(self):
        class MyHandler:
            @aws_response_serializer("sqs-query", "ListQueues")
            def handle(self, request: Request):
                from localstack.aws.api.sqs import ListQueuesResult

                return ListQueuesResult(
                    QueueUrls=[
                        "https://localhost:4566/000000000000/my-queue-1",
                        "https://localhost:4566/000000000000/my-queue-2",
                    ]
                )

        response = MyHandler().handle(
            Request("POST", "/", body="Action=ListQueues", headers={"Accept": "application/json"})
        )
        assert response.status_code == 200
        assert response.json["ListQueuesResponse"]["ListQueuesResult"] == {
            "QueueUrl": [
                "https://localhost:4566/000000000000/my-queue-1",
                "https://localhost:4566/000000000000/my-queue-2",
            ]
        }
