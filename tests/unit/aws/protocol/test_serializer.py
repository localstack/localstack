import copy
import re
from datetime import datetime

import pytest
from botocore.parsers import ResponseParser, create_parser
from dateutil.tz import tzutc

from localstack.aws.api import CommonServiceException, ServiceException
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.spec import load_service
from localstack.utils.common import to_str

_skip_assert = {}


def _botocore_serializer_integration_test(
    service: str,
    action: str,
    response: dict,
    status_code=200,
    expected_response_content: dict = None,
):
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
    :return: None
    """

    # Load the appropriate service
    service = load_service(service)

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    # The serializer changes the incoming dict, therefore copy it before passing it to the serializer
    response_to_parse = copy.deepcopy(response)
    serialized_response = response_serializer.serialize_to_response(
        response_to_parse, service.operation_model(action)
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
    assert len(parsed_response["ResponseMetadata"]["RequestId"]) == 52
    del parsed_response["ResponseMetadata"]

    if expected_response_content is None:
        expected_response_content = response
    if expected_response_content is not _skip_assert:
        assert parsed_response == expected_response_content

    return return_response


def _botocore_error_serializer_integration_test(
    service: str,
    action: str,
    exception: ServiceException,
    code: str,
    status_code: int,
    message: str,
):
    """
    Performs an integration test for the error serialization using botocore as parser.
    It executes the following steps:
    - Load the given service (f.e. "sqs")
    - Serialize the _error_ response with the appropriate serializer from the AWS Serivce Framework
    - Parse the serialized error response using the botocore parser
    - Checks the the metadata is correct (status code, requestID,...)
    - Checks if the parsed error response content is correct

    :param service: to load the correct service specification, serializer, and parser
    :param action: to load the correct service specification, serializer, and parser
    :param exception: which should be serialized and tested against
    :param code: expected "code" of the exception (i.e. the AWS specific exception ID, f.e.
                 "CloudFrontOriginAccessIdentityAlreadyExists")
    :param status_code: expected HTTP response status code
    :param message: expected error message
    :return: None
    """

    # Load the appropriate service
    service = load_service(service)

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model(action)
    )

    # Use the parser from botocore to parse the serialized response
    response_parser: ResponseParser = create_parser(service.protocol)
    parsed_response = response_parser.parse(
        serialized_response.to_readonly_response_dict(),
        service.operation_model(action).output_shape,
    )

    # Check if the result is equal to the initial response params
    assert "Error" in parsed_response
    assert "Code" in parsed_response["Error"]
    assert "Message" in parsed_response["Error"]
    assert parsed_response["Error"]["Code"] == code
    assert parsed_response["Error"]["Message"] == message

    assert "ResponseMetadata" in parsed_response
    assert "RequestId" in parsed_response["ResponseMetadata"]
    assert len(parsed_response["ResponseMetadata"]["RequestId"]) == 52
    assert "HTTPStatusCode" in parsed_response["ResponseMetadata"]
    assert parsed_response["ResponseMetadata"]["HTTPStatusCode"] == status_code


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


@pytest.mark.skip(reason="failing! 'Body' has 'streaming=True'!")
def test_rest_xml_serializer_s3_2_with_botocore():
    parameters = {
        # TODO
        # 'Body': StreamingBody(),
        "Body": "Fuu",
        "DeleteMarker": True,
        "AcceptRanges": "string",
        "Expiration": "string",
        "Restore": "string",
        "LastModified": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
        "ContentLength": 123,
        "ETag": "string",
        "MissingMeta": 123,
        "VersionId": "string",
        "CacheControl": "string",
        "ContentDisposition": "string",
        "ContentEncoding": "string",
        "ContentLanguage": "string",
        "ContentRange": "string",
        "ContentType": "string",
        "Expires": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
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
        "ObjectLockRetainUntilDate": datetime(2015, 1, 1, 23, 59, 59, 6000, tzinfo=tzutc()),
        "ObjectLockLegalHoldStatus": "ON",
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
    # Specific error of the SendMessage operation in SQS as the scaffold would generate it
    class InvalidMessageContents(ServiceException):
        """The message contains characters outside the allowed set."""

        pass

    exception = InvalidMessageContents("Exception message!")
    _botocore_error_serializer_integration_test(
        "sqs", "SendMessage", exception, "InvalidMessageContents", 400, "Exception message!"
    )


def test_query_protocol_error_serialization_plain():
    # Specific error of the ChangeMessageVisibility operation in SQS as the scaffold would generate it
    class ReceiptHandleIsInvalid(ServiceException):
        pass

    exception = ReceiptHandleIsInvalid(
        'The input receipt handle "garbage" is not a valid receipt handle.'
    )

    # Load the SQS service
    service = load_service("sqs")

    # Use our serializer to serialize the response
    response_serializer = create_serializer(service)
    serialized_response = response_serializer.serialize_error_to_response(
        exception, service.operation_model("ChangeMessageVisibility")
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
        "sqs", "SendMessage", exception, "InvalidParameterValue", 400, "Parameter x was invalid!"
    )


def test_restxml_protocol_error_serialization():
    class CloudFrontOriginAccessIdentityAlreadyExists(ServiceException):
        pass

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


def test_json_protocol_error_serialization():
    class UserPoolTaggingException(ServiceException):
        pass

    exception = UserPoolTaggingException("Exception message!")
    _botocore_error_serializer_integration_test(
        "cognito-idp",
        "CreateUserPool",
        exception,
        "UserPoolTaggingException",
        400,
        "Exception message!",
    )


def test_json_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "APIAccessCensorship",
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        status_code=451,
    )
    _botocore_error_serializer_integration_test(
        "cognito-idp",
        "CreateUserPool",
        exception,
        "APIAccessCensorship",
        451,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
    )


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


def test_restjson_protocol_error_serialization():
    class ThrottledException(ServiceException):
        pass

    exception = ThrottledException("Exception message!")
    _botocore_error_serializer_integration_test(
        "xray",
        "UpdateSamplingRule",
        exception,
        "ThrottledException",
        429,
        "Exception message!",
    )


def test_restjson_protocol_custom_error_serialization():
    exception = CommonServiceException(
        "APIAccessCensorship",
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
        status_code=451,
    )
    _botocore_error_serializer_integration_test(
        "xray",
        "UpdateSamplingRule",
        exception,
        "APIAccessCensorship",
        451,
        "You shall not access this API! Sincerely, your friendly neighbourhood firefighter.",
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


def test_restxml_headers_location():
    """Tests fields with the location trait "headers" for rest-xml."""
    _botocore_serializer_integration_test(
        "s3",
        "HeadObject",
        {
            "DeleteMarker": False,
            "Metadata": {"headers_key1": "headers_value1", "headers_key2": "headers_value2"},
        },
        # The spec defines the ContentType and the ContentLength, which is automatically set
        expected_response_content={
            "DeleteMarker": False,
            "Metadata": {"headers_key1": "headers_value1", "headers_key2": "headers_value2"},
            "ContentType": "text/xml",
            "ContentLength": 59,
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


def test_all_non_existing_key():
    """Tests the different protocols to allow non-existing keys in strucutres / dicts."""
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
