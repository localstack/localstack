from datetime import datetime
from urllib.parse import urlencode

from botocore.serialize import create_serializer

from localstack.aws.api import HttpRequest
from localstack.aws.protocol.parser import QueryRequestParser, create_parser
from localstack.aws.spec import load_service
from localstack.utils.common import to_bytes


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
        headers={},
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
        headers={},
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
        headers={},
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
        headers={},
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
        headers={},
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
        headers={},
        path="",
    )
    operation, params = parser.parse(request)
    assert operation.name == "DeleteMessageBatch"
    assert params == {
        "QueueUrl": "http://localhost:4566/000000000000/tf-acc-test-queue",
        "Entries": [{"Id": "bar", "ReceiptHandle": "foo"}, {"Id": "bar", "ReceiptHandle": "foo"}],
    }


def _botocore_parser_integration_test(
    service: str, action: str, headers: dict = None, expected: dict = None, **kwargs
):
    # Load the appropriate service
    service = load_service(service)
    # Use the serializer from botocore to serialize the request params
    serializer = create_serializer(service.protocol)

    serialized_request = serializer.serialize_to_request(kwargs, service.operation_model(action))
    body = serialized_request["body"]

    if service.protocol in ["query", "ec2"]:
        # Serialize the body as query parameter
        body = urlencode(serialized_request["body"])

    # Use our parser to parse the serialized body
    parser = create_parser(service)
    operation_model, parsed_request = parser.parse(
        HttpRequest(
            method=serialized_request.get("method") or "GET",
            path=serialized_request.get("url_path") or "",
            query_string=serialized_request.get("query_string") or "",
            headers=headers,
            body=body,
        )
    )

    # Check if the result is equal to the given "expected" dict or the kwargs (if "expected" has not been set)
    assert parsed_request == (expected or kwargs)


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
        expected={"QueueUrl": "string", "Entries": None},
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


# TODO Add additional tests (or even automate the creation)
# - Go to the Boto3 Docs (https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/index.html)
# - Look for boto3 request syntax definition for services that use the protocol you want to test
# - Take request syntax, remove the "or" ("|") and call the helper function with these named params
