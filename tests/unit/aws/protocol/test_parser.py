from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import unquote, urlencode, urlsplit

import pytest
from botocore.awsrequest import prepare_request_dict
from botocore.serialize import create_serializer

from localstack import config
from localstack.aws.protocol.parser import (
    OperationNotFoundParserError,
    ProtocolParserError,
    QueryRequestParser,
    RestJSONRequestParser,
    UnknownParserError,
    create_parser,
)
from localstack.aws.spec import load_service
from localstack.http import Request as HttpRequest
from localstack.services.s3 import s3_utils
from localstack.utils.common import to_bytes, to_str


def test_query_parser():
    """Basic test for the QueryParser with a simple example (SQS SendMessage request)."""
    parser = QueryRequestParser(load_service("sqs"))
    request = HttpRequest(
        body=to_bytes(
            "Action=SendMessage&Version=2012-11-05&"
            "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
            "MessageBody=%7B%22foo%22%3A+%22bared%22%7D&"
            "DelaySeconds=2"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "SendMessage"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/tf-acc-test-queue",
        "MessageBody": '{"foo": "bared"}',
        "DelaySeconds": 2,
    }


def test_sqs_parse_tag_map_with_member_name_as_location():
    # see https://github.com/localstack/localstack/issues/4391
    parser = create_parser(load_service("sqs"))

    # with "Tag." it works (this is the default request)
    request = HttpRequest(
        "POST",
        "/",
        body="Action=TagQueue&"
        "Version=2012-11-05&"
        "QueueUrl=http://localhost:4566/000000000000/foobar&"
        "Tag.1.Key=returnly%3Aenv&"
        "Tag.1.Value=local&"
        "Tag.2.Key=returnly%3Acreator&"
        "Tag.2.Value=rma-api-svc",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    operation, params = parser.parse(request)
    assert operation.name == "TagQueue"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/foobar",
        "Tags": {"returnly:creator": "rma-api-svc", "returnly:env": "local"},
    }

    # apparently this is how the Java AWS SDK generates the TagQueue request, see see
    # https://github.com/localstack/localstack/issues/4391
    request = HttpRequest(
        "POST",
        "/",
        body="Action=TagQueue&"
        "Version=2012-11-05&"
        "QueueUrl=http://localhost:4566/000000000000/foobar&"
        "Tags.1.Key=returnly%3Aenv&"
        "Tags.1.Value=local&"
        "Tags.2.Key=returnly%3Acreator&"
        "Tags.2.Value=rma-api-svc",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    operation, params = parser.parse(request)
    assert operation.name == "TagQueue"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/foobar",
        "Tags": {"returnly:creator": "rma-api-svc", "returnly:env": "local"},
    }


def test_query_parser_uri():
    """
    Basic test for the QueryParser with a simple example (SQS SendMessage request),
    where the parameters are encoded in the URI instead of the body.
    """
    parser = QueryRequestParser(load_service("sqs"))
    request = HttpRequest(
        query_string="Action=SendMessage&Version=2012-11-05&"
        "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
        "MessageBody=%7B%22foo%22%3A+%22bared%22%7D&"
        "DelaySeconds=2",
        method="POST",
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "SendMessage"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/tf-acc-test-queue",
        "MessageBody": '{"foo": "bared"}',
        "DelaySeconds": 2,
    }


def test_query_parser_flattened_map():
    """Simple test with a flattened map (SQS SetQueueAttributes request)."""
    parser = QueryRequestParser(load_service("sqs"))
    request = HttpRequest(
        body=to_bytes(
            "Action=SetQueueAttributes&Version=2012-11-05&"
            "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
            "Attribute.1.Name=DelaySeconds&"
            "Attribute.1.Value=10&"
            "Attribute.2.Name=MaximumMessageSize&"
            "Attribute.2.Value=131072&"
            "Attribute.3.Name=MessageRetentionPeriod&"
            "Attribute.3.Value=259200&"
            "Attribute.4.Name=ReceiveMessageWaitTimeSeconds&"
            "Attribute.4.Value=20&"
            "Attribute.5.Name=RedrivePolicy&"
            "Attribute.5.Value=%7B%22deadLetterTargetArn%22%3A%22arn%3Aaws%3Asqs%3Aus-east-1%3A80398EXAMPLE%3AMyDeadLetterQueue%22%2C%22maxReceiveCount%22%3A%221000%22%7D&"
            "Attribute.6.Name=VisibilityTimeout&Attribute.6.Value=60"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "SetQueueAttributes"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/tf-acc-test-queue",
        "Attributes": {
            "DelaySeconds": "10",
            "MaximumMessageSize": "131072",
            "MessageRetentionPeriod": "259200",
            "ReceiveMessageWaitTimeSeconds": "20",
            "RedrivePolicy": '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:80398EXAMPLE:MyDeadLetterQueue","maxReceiveCount":"1000"}',
            "VisibilityTimeout": "60",
        },
    }


def test_query_parser_non_flattened_map():
    """Simple test with a flattened map (SQS SetQueueAttributes request)."""
    parser = QueryRequestParser(load_service("sns"))
    request = HttpRequest(
        body=to_bytes(
            "Action=SetEndpointAttributes&"
            "EndpointArn=arn%3Aaws%3Asns%3Aus-west-2%3A123456789012%3Aendpoint%2FGCM%2Fgcmpushapp%2F5e3e9847-3183-3f18-a7e8-671c3a57d4b3&"
            "Attributes.entry.1.key=CustomUserData&"
            "Attributes.entry.1.value=My+custom+userdata&"
            "Version=2010-03-31&"
            "AUTHPARAMS"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "SetEndpointAttributes"
    assert params == {
        "Attributes": {"CustomUserData": "My custom userdata"},
        "EndpointArn": "arn:aws:sns:us-west-2:123456789012:endpoint/GCM/gcmpushapp/5e3e9847-3183-3f18-a7e8-671c3a57d4b3",
    }


def test_query_parser_non_flattened_list_structure():
    """Simple test with a non-flattened list structure (CloudFormation CreateChangeSet)."""
    parser = QueryRequestParser(load_service("cloudformation"))
    request = HttpRequest(
        body=to_bytes(
            "Action=CreateChangeSet&"
            "ChangeSetName=SampleChangeSet&"
            "Parameters.member.1.ParameterKey=KeyName&"
            "Parameters.member.1.UsePreviousValue=true&"
            "Parameters.member.2.ParameterKey=Purpose&"
            "Parameters.member.2.ParameterValue=production&"
            "StackName=arn:aws:cloudformation:us-east-1:123456789012:stack/SampleStack/1a2345b6-0000-00a0-a123-00abc0abc000&"
            "UsePreviousTemplate=true&"
            "Version=2010-05-15&"
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&"
            "X-Amz-Credential=[Access-key-ID-and-scope]&"
            "X-Amz-Date=20160316T233349Z&"
            "X-Amz-SignedHeaders=content-type;host&"
            "X-Amz-Signature=[Signature]"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "CreateChangeSet"
    assert params == {
        "StackName": "arn:aws:cloudformation:us-east-1:123456789012:stack/SampleStack/1a2345b6-0000-00a0-a123-00abc0abc000",
        "UsePreviousTemplate": True,
        "Parameters": [
            {"ParameterKey": "KeyName", "UsePreviousValue": True},
            {"ParameterKey": "Purpose", "ParameterValue": "production"},
        ],
        "ChangeSetName": "SampleChangeSet",
    }


def test_query_parser_non_flattened_list_structure_changed_name():
    """Simple test with a non-flattened list structure where the name of the list differs from the shape's name
    (CloudWatch PutMetricData)."""
    parser = QueryRequestParser(load_service("cloudwatch"))
    request = HttpRequest(
        body=to_bytes(
            "Action=PutMetricData&"
            "Version=2010-08-01&"
            "Namespace=TestNamespace&"
            "MetricData.member.1.MetricName=buffers&"
            "MetricData.member.1.Unit=Bytes&"
            "MetricData.member.1.Value=231434333&"
            "MetricData.member.1.Dimensions.member.1.Name=InstanceType&"
            "MetricData.member.1.Dimensions.member.1.Value=m1.small&"
            "AUTHPARAMS"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "PutMetricData"
    assert params == {
        "MetricData": [
            {
                "Dimensions": [{"Name": "InstanceType", "Value": "m1.small"}],
                "MetricName": "buffers",
                "Unit": "Bytes",
                "Value": 231434333.0,
            }
        ],
        "Namespace": "TestNamespace",
    }


def test_query_parser_flattened_list_structure():
    """Simple test with a flattened list of structures."""
    parser = QueryRequestParser(load_service("sqs"))
    request = HttpRequest(
        body=to_bytes(
            "Action=DeleteMessageBatch&"
            "Version=2012-11-05&"
            "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
            "DeleteMessageBatchRequestEntry.1.Id=bar&"
            "DeleteMessageBatchRequestEntry.1.ReceiptHandle=foo&"
            "DeleteMessageBatchRequestEntry.2.Id=bar&"
            "DeleteMessageBatchRequestEntry.2.ReceiptHandle=foo"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "DeleteMessageBatch"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/tf-acc-test-queue",
        "Entries": [{"Id": "bar", "ReceiptHandle": "foo"}, {"Id": "bar", "ReceiptHandle": "foo"}],
    }


def test_query_parser_pass_str_as_int_raises_error():
    """Test to make sure that invalid types correctly raise a ProtocolParserError."""
    parser = QueryRequestParser(load_service("sts"))
    request = HttpRequest(
        body=to_bytes(
            "Action=AssumeRole&"
            "RoleArn=arn:aws:iam::000000000000:role/foobared&"
            "RoleSessionName=foobared&"
            "DurationSeconds=abcd"  # illegal argument (should be an int)
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    with pytest.raises(ProtocolParserError):
        parser.parse(request)


def _botocore_parser_integration_test(
    service: str, action: str, headers: dict = None, expected: dict = None, **kwargs
):
    # Load the appropriate service
    service = load_service(service)
    # Use the serializer from botocore to serialize the request params
    serializer = create_serializer(service.protocol)

    operation_model = service.operation_model(action)
    serialized_request = serializer.serialize_to_request(kwargs, operation_model)

    # botocore >= 1.28 might modify the url path of the request dict (specifically for S3).
    # It will then set the original url path as "auth_path". If the auth_path is set, we reset the url_path.
    if auth_path := serialized_request.get("auth_path"):
        serialized_request["url_path"] = auth_path

    prepare_request_dict(serialized_request, "")
    split_url = urlsplit(serialized_request.get("url"))
    path = split_url.path
    query_string = split_url.query
    body = serialized_request["body"]
    # use custom headers (if provided), or headers from serialized request as default
    headers = serialized_request.get("headers") if headers is None else headers

    if service.protocol in ["query", "ec2"]:
        # Serialize the body as query parameter
        body = urlencode(serialized_request["body"])

    # Use our parser to parse the serialized body
    parser = create_parser(service)
    parsed_operation_model, parsed_request = parser.parse(
        HttpRequest(
            method=serialized_request.get("method") or "GET",
            path=unquote(path),
            query_string=to_str(query_string),
            headers=headers,
            body=body,
            raw_path=path,
        )
    )

    # Check if the determined operation_model is correct
    assert parsed_operation_model == operation_model

    # Check if the result is equal to the given "expected" dict or the kwargs (if "expected" has not been set)
    expected = expected or kwargs
    # The parser adds None for none-existing members on purpose. Remove those for the assert
    expected = {key: value for key, value in expected.items() if value is not None}
    parsed_request = {key: value for key, value in parsed_request.items() if value is not None}
    assert parsed_request == expected


def test_query_parser_sqs_with_botocore():
    _botocore_parser_integration_test(
        service="sqs",
        action="SendMessage",
        QueueUrl="string",
        MessageBody="string",
        DelaySeconds=123,
        MessageAttributes={
            "string": {
                "StringValue": "string",
                "BinaryValue": b"bytes",
                "StringListValues": [
                    "string",
                ],
                "BinaryListValues": [
                    b"bytes",
                ],
                "DataType": "string",
            }
        },
        MessageSystemAttributes={
            "string": {
                "StringValue": "string",
                "BinaryValue": b"bytes",
                "StringListValues": [
                    "string",
                ],
                "BinaryListValues": [
                    b"bytes",
                ],
                "DataType": "string",
            }
        },
        MessageDeduplicationId="string",
        MessageGroupId="string",
    )


def test_query_parser_empty_required_members_sqs_with_botocore():
    _botocore_parser_integration_test(
        service="sqs",
        action="SendMessageBatch",
        QueueUrl="string",
        Entries=[],
        expected={"QueueUrl": "string"},
    )


def test_query_parser_no_input_shape_autoscaling_with_botocore():
    _botocore_parser_integration_test(
        service="autoscaling",
        action="DescribeMetricCollectionTypes",
    )


def test_query_parser_cloudformation_with_botocore():
    _botocore_parser_integration_test(
        service="cloudformation",
        action="CreateStack",
        StackName="string",
        TemplateBody="string",
        TemplateURL="string",
        Parameters=[
            {
                "ParameterKey": "string",
                "ParameterValue": "string",
                "UsePreviousValue": True,
                "ResolvedValue": "string",
            },
        ],
        DisableRollback=False,
        RollbackConfiguration={
            "RollbackTriggers": [
                {"Arn": "string", "Type": "string"},
            ],
            "MonitoringTimeInMinutes": 123,
        },
        TimeoutInMinutes=123,
        NotificationARNs=[
            "string",
        ],
        Capabilities=[
            "CAPABILITY_IAM",
        ],
        ResourceTypes=[
            "string",
        ],
        RoleARN="12345678901234567890",
        OnFailure="DO_NOTHING",
        StackPolicyBody="string",
        StackPolicyURL="string",
        Tags=[
            {"Key": "string", "Value": "string"},
        ],
        ClientRequestToken="string",
        EnableTerminationProtection=False,
    )


def test_query_parser_unflattened_list_of_maps():
    _botocore_parser_integration_test(
        service="rds",
        action="CreateDBCluster",
        DBClusterIdentifier="mydbcluster",
        Engine="aurora",
        Tags=[{"Key": "Hello", "Value": "There"}, {"Key": "Hello1", "Value": "There1"}],
    )


def test_restxml_parser_route53_with_botocore():
    _botocore_parser_integration_test(
        service="route53",
        action="CreateHostedZone",
        Name="string",
        VPC={"VPCRegion": "us-east-1", "VPCId": "string"},
        CallerReference="string",
        HostedZoneConfig={"Comment": "string", "PrivateZone": True},
        DelegationSetId="string",
    )


def test_json_parser_cognito_with_botocore():
    _botocore_parser_integration_test(
        service="cognito-idp",
        action="CreateUserPool",
        headers={"X-Amz-Target": "AWSCognitoIdentityProviderService.CreateUserPool"},
        PoolName="string",
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 123,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "TemporaryPasswordValidityDays": 123,
            }
        },
        LambdaConfig={
            "PreSignUp": "12345678901234567890",
            "CustomMessage": "12345678901234567890",
            "PostConfirmation": "12345678901234567890",
            "PreAuthentication": "12345678901234567890",
            "PostAuthentication": "12345678901234567890",
            "DefineAuthChallenge": "12345678901234567890",
            "CreateAuthChallenge": "12345678901234567890",
            "VerifyAuthChallengeResponse": "12345678901234567890",
            "PreTokenGeneration": "12345678901234567890",
            "UserMigration": "12345678901234567890",
            "CustomSMSSender": {"LambdaVersion": "V1_0", "LambdaArn": "12345678901234567890"},
            "CustomEmailSender": {"LambdaVersion": "V1_0", "LambdaArn": "12345678901234567890"},
            "KMSKeyID": "12345678901234567890",
        },
        AutoVerifiedAttributes=[
            "phone_number",
        ],
        AliasAttributes=[
            "phone_number",
        ],
        UsernameAttributes=[
            "phone_number",
        ],
        SmsVerificationMessage="string",
        EmailVerificationMessage="string",
        EmailVerificationSubject="string",
        VerificationMessageTemplate={
            "SmsMessage": "string",
            "EmailMessage": "string",
            "EmailSubject": "string",
            "EmailMessageByLink": "string",
            "EmailSubjectByLink": "string",
            "DefaultEmailOption": "CONFIRM_WITH_LINK",
        },
        SmsAuthenticationMessage="string",
        MfaConfiguration="OFF",
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": True,
            "DeviceOnlyRememberedOnUserPrompt": True,
        },
        EmailConfiguration={
            "SourceArn": "12345678901234567890",
            "ReplyToEmailAddress": "string",
            "EmailSendingAccount": "COGNITO_DEFAULT",
            "From": "string",
            "ConfigurationSet": "string",
        },
        SmsConfiguration={"SnsCallerArn": "12345678901234567890", "ExternalId": "string"},
        UserPoolTags={"string": "string"},
        AdminCreateUserConfig={
            "AllowAdminCreateUserOnly": True,
            "UnusedAccountValidityDays": 123,
            "InviteMessageTemplate": {
                "SMSMessage": "string",
                "EmailMessage": "string",
                "EmailSubject": "string",
            },
        },
        Schema=[
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
        UserPoolAddOns={"AdvancedSecurityMode": "OFF"},
        UsernameConfiguration={"CaseSensitive": True},
        AccountRecoverySetting={
            "RecoveryMechanisms": [
                {"Priority": 123, "Name": "verified_email"},
            ]
        },
    )


def test_json_cbor_blob_parsing():
    serialized_request = {
        "url_path": "/",
        "query_string": "",
        "method": "POST",
        "headers": {
            "Host": "localhost:4566",
            "amz-sdk-invocation-id": "d77968c6-b536-155d-7228-d4dfe6372154",
            "amz-sdk-request": "attempt=1; max=3",
            "Content-Length": "103",
            "Content-Type": "application/x-amz-cbor-1.1",
            "X-Amz-Date": "20220721T081553Z",
            "X-Amz-Target": "Kinesis_20131202.PutRecord",
            "x-localstack-tgt-api": "kinesis",
        },
        "body": b"\xbfjStreamNamedtestdDataMhello, world!lPartitionKeylpartitionkey\xff",
        "url": "/",
        "context": {},
    }

    prepare_request_dict(serialized_request, "")
    split_url = urlsplit(serialized_request.get("url"))
    path = split_url.path
    query_string = split_url.query

    # Use our parser to parse the serialized body
    # Load the appropriate service
    service = load_service("kinesis")
    operation_model = service.operation_model("PutRecord")
    parser = create_parser(service)
    parsed_operation_model, parsed_request = parser.parse(
        HttpRequest(
            method=serialized_request.get("method") or "GET",
            path=unquote(path),
            query_string=to_str(query_string),
            headers=serialized_request.get("headers"),
            body=serialized_request["body"],
            raw_path=path,
        )
    )

    # Check if the determined operation_model is correct
    assert parsed_operation_model == operation_model

    assert "Data" in parsed_request
    assert parsed_request["Data"] == b"hello, world!"
    assert "StreamName" in parsed_request
    assert parsed_request["StreamName"] == "test"
    assert "PartitionKey" in parsed_request
    assert parsed_request["PartitionKey"] == "partitionkey"


def test_restjson_parser_xray_with_botocore():
    _botocore_parser_integration_test(
        service="xray",
        action="PutTelemetryRecords",
        TelemetryRecords=[
            {
                "Timestamp": datetime(2015, 1, 1),
                "SegmentsReceivedCount": 123,
                "SegmentsSentCount": 123,
                "SegmentsSpilloverCount": 123,
                "SegmentsRejectedCount": 123,
                "BackendConnectionErrors": {
                    "TimeoutCount": 123,
                    "ConnectionRefusedCount": 123,
                    "HTTPCode4XXCount": 123,
                    "HTTPCode5XXCount": 123,
                    "UnknownHostCount": 123,
                    "OtherCount": 123,
                },
            },
        ],
        EC2InstanceId="string",
        Hostname="string",
        ResourceARN="string",
    )


def test_restjson_path_location_opensearch_with_botocore():
    _botocore_parser_integration_test(
        service="opensearch",
        action="DeleteDomain",
        DomainName="test-domain",
    )


def test_restjson_query_location_opensearch_with_botocore():
    _botocore_parser_integration_test(
        service="opensearch",
        action="ListVersions",
        NextToken="test-token",
    )


def test_restjson_opensearch_with_botocore():
    _botocore_parser_integration_test(
        service="opensearch",
        action="UpdateDomainConfig",
        DomainName="string",
        ClusterConfig={
            "InstanceType": "m3.medium.search",
            "InstanceCount": 123,
            "DedicatedMasterEnabled": True,
            "ZoneAwarenessEnabled": True,
            "ZoneAwarenessConfig": {"AvailabilityZoneCount": 123},
            "DedicatedMasterType": "m3.medium.search",
            "DedicatedMasterCount": 123,
            "WarmEnabled": True,
            "WarmType": "ultrawarm1.medium.search",
            "WarmCount": 123,
            "ColdStorageOptions": {"Enabled": True},
        },
        EBSOptions={"EBSEnabled": False, "VolumeType": "standard", "VolumeSize": 123, "Iops": 123},
        SnapshotOptions={"AutomatedSnapshotStartHour": 123},
        VPCOptions={
            "SubnetIds": [
                "string",
            ],
            "SecurityGroupIds": [
                "string",
            ],
        },
        CognitoOptions={
            "Enabled": True,
            "UserPoolId": "string",
            "IdentityPoolId": "string",
            "RoleArn": "12345678901234567890",
        },
        AdvancedOptions={"string": "string"},
        AccessPolicies="string",
        LogPublishingOptions={
            "string": {"CloudWatchLogsLogGroupArn": "12345678901234567890", "Enabled": True}
        },
        EncryptionAtRestOptions={"Enabled": False, "KmsKeyId": "string"},
        DomainEndpointOptions={
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": "Policy-Min-TLS-1-0-2019-07",
            "CustomEndpointEnabled": True,
            "CustomEndpoint": "string",
            "CustomEndpointCertificateArn": "12345678901234567890",
        },
        NodeToNodeEncryptionOptions={"Enabled": True},
        AdvancedSecurityOptions={
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            "MasterUserOptions": {
                "MasterUserARN": "12345678901234567890",
                "MasterUserName": "string",
                "MasterUserPassword": "12345678",
            },
            "SAMLOptions": {
                "Enabled": True,
                "Idp": {"MetadataContent": "string", "EntityId": "12345678"},
                "MasterUserName": "string",
                "MasterBackendRole": "string",
                "SubjectKey": "string",
                "RolesKey": "string",
                "SessionTimeoutMinutes": 123,
            },
        },
        AutoTuneOptions={
            "DesiredState": "ENABLED",
            "RollbackOnDisable": "DEFAULT_ROLLBACK",
            "MaintenanceSchedules": [
                {
                    "StartAt": datetime(2015, 1, 1),
                    "Duration": {"Value": 123, "Unit": "HOURS"},
                    "CronExpressionForRecurrence": "string",
                },
            ],
        },
    )


def test_restjson_awslambda_invoke_with_botocore():
    _botocore_parser_integration_test(
        service="lambda",
        action="Invoke",
        FunctionName="test-function",
    )


def test_ec2_parser_ec2_with_botocore():
    _botocore_parser_integration_test(
        service="ec2",
        action="CreateImage",
        BlockDeviceMappings=[
            {
                "DeviceName": "string",
                "VirtualName": "string",
                "Ebs": {
                    "DeleteOnTermination": True,
                    "Iops": 123,
                    "SnapshotId": "string",
                    "VolumeSize": 123,
                    "VolumeType": "standard",
                    "KmsKeyId": "string",
                    "Throughput": 123,
                    "OutpostArn": "string",
                    "Encrypted": True,
                },
                "NoDevice": "string",
            },
        ],
        Description="string",
        DryRun=True | False,
        InstanceId="string",
        Name="string",
        NoReboot=True | False,
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [
                    {"Key": "string", "Value": "string"},
                ],
            },
        ],
    )


def test_restjson_parser_path_params_with_slashes():
    _botocore_parser_integration_test(
        service="qldb",
        action="ListTagsForResource",
        ResourceArn="arn:aws:qldb:eu-central-1:000000000000:ledger/c-c67c827a",
    )


def test_parse_cloudtrail_with_botocore():
    _botocore_parser_integration_test(
        service="cloudtrail",
        action="DescribeTrails",
        trailNameList=["t1"],
    )


def test_parse_cloudfront_uri_location_with_botocore():
    _botocore_parser_integration_test(
        service="cloudfront",
        action="GetDistribution",
        Id="001",
    )


def test_parse_cloudfront_payload_with_botocore():
    _botocore_parser_integration_test(
        service="cloudfront",
        action="CreateOriginRequestPolicy",
        OriginRequestPolicyConfig={
            "Comment": "comment1",
            "Name": "name",
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "all"},
            "QueryStringsConfig": {"QueryStringBehavior": "all"},
        },
    )


def test_parse_opensearch_conflicting_request_uris():
    """
    Tests if the operation detection works with conflicting regular expressions:
    - OpenSearch's DescribeDomain (/2021-01-01/opensearch/domain/{DomainName})
    - OpenSearch's DescribeDomainConfig (/2021-01-01/opensearch/domain/{DomainName}/config)
    Since the path parameters are greedy (they might contain slashes), "better" matches need to be preferred.
    """
    _botocore_parser_integration_test(
        service="opensearch",
        action="DescribeDomainConfig",
        DomainName="test-domain",
    )
    _botocore_parser_integration_test(
        service="opensearch",
        action="DescribeDomain",
        DomainName="test-domain",
    )


def test_parse_appconfig_non_json_blob_payload():
    """
    Tests if the parsing works correctly if the request contains a blob payload shape which does not contain valid JSON.
    """
    _botocore_parser_integration_test(
        service="appconfig",
        action="CreateHostedConfigurationVersion",
        ApplicationId="test-application-id",
        ConfigurationProfileId="test-configuration-profile-id",
        Content=BytesIO(b"<html></html>"),
        ContentType="application/html",
    )


def test_parse_appconfig_deprecated_operation():
    """
    Tests if the parsing works correctly if the request targets a deprecated operation (without alternative, i.e.
    another function having the same signature).
    """
    _botocore_parser_integration_test(
        service="appconfig",
        action="GetConfiguration",
        Application="test-application",
        Environment="test-environment",
        Configuration="test-configuration",
        ClientId="test-client-id",
    )


def test_parse_s3_with_extended_uri_pattern():
    """
    Tests if the parsing works for operations where the operation defines a request URI with a "+" in the variable name,
    (for example "requestUri":"/{Bucket}/{Key+}").
    The parameter with the "+" directive is greedy. There can only be one explicitly greedy param.
    The corresponding shape definition does not contain the "+" in the "locationName" directive.
    """
    _botocore_parser_integration_test(
        service="s3", action="ListParts", Bucket="foo", Key="bar/test", UploadId="test-upload-id"
    )


def test_parse_s3_utf8_url():
    """Test the parsing of a map with the location trait 'headers'."""
    _botocore_parser_integration_test(
        service="s3",
        action="PutObject",
        ContentLength=0,
        Bucket="test-bucket",
        Key="Ā0",
        Metadata={"Key": "value", "Key2": "value2"},
    )


def test_parse_restjson_uri_location():
    """Tests if the parsing of uri parameters works correctly for the rest-json protocol"""
    _botocore_parser_integration_test(
        service="lambda",
        action="AddPermission",
        Action="lambda:InvokeFunction",
        FunctionName="arn:aws:lambda:us-east-1:000000000000:function:test-forward-sns",
        Principal="sns.amazonaws.com",
        StatementId="2e25f762",
    )


def test_parse_restjson_header_parsing():
    """Tests parsing shapes from the header location."""
    _botocore_parser_integration_test(
        service="ebs",
        action="CompleteSnapshot",
        SnapshotId="123",
        ChangedBlocksCount=5,
        Checksum="test-checksum-header-field",
    )


def test_parse_restjson_querystring_list_parsing():
    """Tests the parsing of lists of shapes with location querystring."""
    _botocore_parser_integration_test(
        service="amplify",
        action="UntagResource",
        resourceArn="arn:aws:lambda:us-east-1:000000000000:function:test-forward-sns",
        tagKeys=["Tag1", "Tag2"],
    )


def test_restjson_operation_detection_with_query_suffix_in_requesturi():
    """
    Test if the correct operation is detected if the requestURI pattern of the specification contains the first query
    parameter, f.e. API Gateway's ImportRestApi: "/restapis?mode=import
    """
    _botocore_parser_integration_test(
        service="apigateway",
        action="ImportRestApi",
        body=BytesIO(b"Test"),
    )


def test_rest_url_parameter_with_dashes():
    """
    Test if requestUri parameters with dashes in them (e.g., "/v2/tags/{resource-arn}") are parsed correctly.
    """
    _botocore_parser_integration_test(
        service="apigatewayv2",
        action="GetTags",
        ResourceArn="arn:aws:apigatewayv2:us-east-1:000000000000:foobar",
    )


def test_rest_url_parameter_with_slashes():
    """Test if the parsing works for requests with (encoded) slashes in a parameter."""
    _botocore_parser_integration_test(
        service="backup",
        action="ListRecoveryPointsByResource",
        ResourceArn="arn:aws:dynamodb:us-east-1:000000000000:table/table-104f455b",
    )


def test_restxml_operation_detection_with_query_suffix_without_value_in_requesturi():
    """
    Test if the correct operation is detected if the requestURI pattern of the specification contains the first query
    parameter without a specific value, f.e. CloudFront's CreateDistributionWithTags:
    "/2020-05-31/distribution?WithTags"
    """
    _botocore_parser_integration_test(
        service="cloudfront",
        action="CreateDistributionWithTags",
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": "string",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "string",
                            "DomainName": "string",
                        }
                    ],
                },
                "Comment": "string",
                "Enabled": True,
                "DefaultCacheBehavior": {
                    "TargetOriginId": "string",
                    "ViewerProtocolPolicy": "allow-all",
                },
            },
            "Tags": {
                "Items": [
                    {"Key": "string", "Value": "string"},
                ]
            },
        },
    )


def test_restjson_operation_detection_with_length_prio():
    """
    Tests if the correct operation is detected if the requestURI patterns are conflicting and the length of the
    normalized regular expression for the path matching solves the conflict.
    For example: The detection of API Gateway PutIntegrationResponse (without the normalization PutMethodResponse would
                    be detected).
    """
    _botocore_parser_integration_test(
        service="apigateway",
        action="PutIntegrationResponse",
        restApiId="rest-api-id",
        resourceId="resource-id",
        httpMethod="POST",
        statusCode="201",
    )


def test_restjson_operation_detection_with_subpath():
    """
    Tests if the operation lookup correctly fails for a subpath of an operation.
    For example: The detection of a URL which is routed through API Gateway.
    """
    service = load_service("apigateway")
    parser = create_parser(service)
    with pytest.raises(OperationNotFoundParserError):
        parser.parse(
            HttpRequest(
                method="GET",
                path="/restapis/cmqinv79uh/local/_user_request_/",
                raw_path="/restapis/cmqinv79uh/local/_user_request_/",
            )
        )


def test_s3_get_operation_detection():
    """
    Test if the S3 operation detection works for ambiguous operations. GetObject is the worst, because it is
    overloaded with the exact same requestURI by another non-deprecated function where the only distinction is the
    matched required parameter.
    """
    _botocore_parser_integration_test(
        service="s3", action="GetObject", Bucket="test-bucket", Key="foo/bar/test.json"
    )


def test_s3_head_operation_detection():
    """Test if the S3 operation detection works for HEAD operations."""
    _botocore_parser_integration_test(
        service="s3", action="HeadObject", Bucket="test-bucket", Key="foo/bar/test.json"
    )


def test_s3_put_object_keys_with_slashes():
    _botocore_parser_integration_test(
        service="s3",
        action="PutObject",
        Bucket="test-bucket",
        Key="/test-key",
        ContentLength=6,
        Body=BytesIO(b"foobar"),
        Metadata={},
    )


def test_s3_get_object_keys_with_slashes():
    _botocore_parser_integration_test(
        service="s3",
        action="GetObject",
        Bucket="test-bucket",
        Key="/test-key",
    )


def test_restxml_headers_parsing():
    """Test the parsing of a map with the location trait 'headers'."""
    _botocore_parser_integration_test(
        service="s3",
        action="PutObject",
        ContentLength=0,
        Bucket="test-bucket",
        Key="test.json",
        Metadata={"Key": "value", "Key2": "value2"},
    )


def test_restxml_header_list_parsing():
    """Tests that list attributes that are encoded into headers are parsed correctly."""
    _botocore_parser_integration_test(
        service="s3",
        action="GetObjectAttributes",
        Bucket="test-bucket",
        Key="/test-key",
        # ObjectAttributesList is a list of strings with location:"header"
        ObjectAttributes=["ObjectSize", "StorageClass"],
    )


def test_restxml_header_date_parsing():
    """Test the parsing of a map with the location trait 'headers'."""
    _botocore_parser_integration_test(
        service="s3",
        action="PutObject",
        Bucket="test-bucket",
        Key="test-key",
        ContentLength=3,
        Body=BytesIO(b"foo"),
        Metadata={},
        Expires=datetime(2015, 1, 1, 0, 0, tzinfo=timezone.utc),
    )


@pytest.mark.skipif(
    not config.LEGACY_S3_PROVIDER, reason="ASF provider does not rely on virtual host parser"
)
def test_s3_virtual_host_addressing():
    """Test the parsing of an S3 bucket request using the bucket encoded in the domain."""
    request = HttpRequest(
        method="PUT", headers={"host": s3_utils.get_bucket_hostname("test-bucket")}
    )
    parser = create_parser(load_service("s3"))
    parsed_operation_model, parsed_request = parser.parse(request)
    assert parsed_operation_model.name == "CreateBucket"
    assert "Bucket" in parsed_request
    assert parsed_request["Bucket"] == "test-bucket"


def test_s3_path_addressing():
    """Test the parsing of an S3 bucket request using the bucket encoded in the path."""
    request = HttpRequest(method="PUT", path="/test-bucket")
    parser = create_parser(load_service("s3"))
    parsed_operation_model, parsed_request = parser.parse(request)
    assert parsed_operation_model.name == "CreateBucket"
    assert "Bucket" in parsed_request
    assert parsed_request["Bucket"] == "test-bucket"


def test_s3_list_buckets_with_localhost():
    # this is the canonical request of `awslocal s3 ls` when running on a standard port
    request = HttpRequest("GET", "/", headers={"host": "localhost"})
    parser = create_parser(load_service("s3"))
    parsed_operation_model, parsed_request = parser.parse(request)
    assert parsed_operation_model.name == "ListBuckets"


def test_s3_list_buckets_with_localhost_and_port():
    # this is the canonical request of `awslocal s3 ls`
    request = HttpRequest("GET", "/", headers={"host": "localhost:4566"})
    parser = create_parser(load_service("s3"))
    parsed_operation_model, parsed_request = parser.parse(request)
    assert parsed_operation_model.name == "ListBuckets"


def test_query_parser_error_on_protocol_error():
    """Test that the parser raises a ProtocolParserError in case of invalid data to parse."""
    parser = QueryRequestParser(load_service("sqs"))
    request = HttpRequest(
        body=to_bytes(
            "Action=UnknownOperation&Version=2012-11-05&"
            "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
            "MessageBody=%7B%22foo%22%3A+%22bared%22%7D&"
            "DelaySeconds=2"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )
    with pytest.raises(ProtocolParserError):
        parser.parse(request)


def test_restjson_parser_error_on_protocol_error():
    request = HttpRequest(
        body="invalid}",
        method="POST",
        path="/2021-01-01/opensearch/domain",
    )
    parser = RestJSONRequestParser(load_service("opensearch"))

    with pytest.raises(ProtocolParserError):
        parser.parse(request)


def test_parser_error_on_unknown_error():
    """Test that the parser raises a UnknownParserError in case of an unknown exception."""
    parser = QueryRequestParser(load_service("sqs"))

    request = HttpRequest(
        body=to_bytes(
            "Action=SendMessage&Version=2012-11-05&"
            "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
            "MessageBody=%7B%22foo%22%3A+%22bared%22%7D&"
            "DelaySeconds=2"
        ),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        path="",
    )

    # An unknown error is obviously hard to trigger (because we would fix it if we would know of a way to trigger it),
    # therefore we patch a function to raise an unexpected error
    def raise_error(*args, **kwargs):
        raise NotImplementedError()

    parser._process_member = raise_error
    with pytest.raises(UnknownParserError):
        parser.parse(request)


def test_restjson_get_element_from_location():
    """
    Some GET requests expect a body. While it is allowed in principle by HTTP, it is discouraged and the server
    should ignore the body of a GET request: https://stackoverflow.com/a/983458/804840.

    However, as of May 7, 2022, the following AWS GET requests expect a JSON body:

    - quicksight GET ListIAMPolicyAssignments (member=AssignmentStatus)
    - sesv2 GET ListContacts (member=Filter)
    - sesv2 GET ListImportJobs (member=ImportDestinationType)
    """

    _botocore_parser_integration_test(
        service="sesv2",
        action="ListContacts",
        ContactListName="foobar",
        Filter={
            "FilteredStatus": "OPT_IN",
            "TopicFilter": {
                "TopicName": "atopic",
                "UseDefaultIfPreferenceUnavailable": False,
            },
        },
    )


def test_restjson_raises_error_on_non_json_body():
    request = HttpRequest("GET", "/2021-01-01/opensearch/domain/mydomain", body="foobar")
    parser = create_parser(load_service("opensearch"))

    with pytest.raises(ProtocolParserError):
        parser.parse(request)


def test_restxml_ignores_get_body():
    request = HttpRequest("GET", "/test-bucket/foo", body="foobar")
    parser = create_parser(load_service("s3"))
    parsed_operation_model, parsed_request = parser.parse(request)
    assert parsed_operation_model.name == "GetObject"
    assert "Bucket" in parsed_request
    assert parsed_request["Bucket"] == "test-bucket"
    assert parsed_request["Key"] == "foo"
