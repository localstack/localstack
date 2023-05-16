import uuid

import pytest

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
    ResourceProviderPayload,
)
from localstack.services.ssm.cfn_resources import SSMParameterAllProperties
from localstack.utils.strings import short_uid


@pytest.mark.skip
def test_manual_deploy(aws_client, aws_client_factory):
    stack_name = f"stack-{short_uid()}"
    stack_id = f"arn:aws:::cloudformation/{stack_name}"

    resource_type = "AWS::SSM::Parameter"

    executor = ResourceProviderExecutor(
        resource_type=resource_type, stack_name=stack_name, stack_id=stack_id
    )

    # definition from the template
    props = SSMParameterAllProperties(Type="String", Value=f"value-{short_uid()}")

    change = {"ResourceChange": {"Action": "Add"}}

    creds = {
        "accessKeyId": "test",
        "secretAccessKey": "test",
        "sessionToken": "",
    }
    resource_provider_payload: ResourceProviderPayload = {
        "awsAccountId": "000000000000",
        "callbackContext": {},
        "stackId": stack_name,
        "resourceType": resource_type,
        "resourceTypeVersion": "000000",
        # TODO: not actually a UUID
        "bearerToken": str(uuid.uuid4()),
        "region": "us-east-1",
        "action": change["ResourceChange"]["Action"],
        "requestData": {
            "logicalResourceId": "MyParameter",
            "resourceProperties": props,
            "previousResourceProperties": None,
            "callerCredentials": creds,
            "providerCredentials": creds,
            "systemTags": {},
            "previousSystemTags": {},
            "stackTags": {},
            "previousStackTags": {},
        },
    }

    event = executor.execute_action(resource_provider_payload)
    assert event.status == OperationStatus.SUCCESS

    res = aws_client.ssm.get_parameter(Name=props.Name)
    assert res["Parameter"]["Value"] == props.Value

    # create the delete event
    resource_provider_payload: ResourceProviderPayload = {
        "awsAccountId": "000000000000",
        "callbackContext": {},
        "stackId": stack_name,
        "resourceType": resource_type,
        "resourceTypeVersion": "000000",
        # TODO: not actually a UUID
        "bearerToken": str(uuid.uuid4()),
        "region": "us-east-1",
        "action": "Remove",
        "requestData": {
            "logicalResourceId": "MyParameter",
            "resourceProperties": props,
            "previousResourceProperties": None,
            "callerCredentials": creds,
            "providerCredentials": creds,
            "systemTags": {},
            "previousSystemTags": {},
            "stackTags": {},
            "previousStackTags": {},
        },
    }
    delete_event = executor.execute_action(resource_provider_payload)
    assert delete_event.status == OperationStatus.SUCCESS
