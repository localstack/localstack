import uuid

import pytest

from localstack.services.cloudformation.resource_provider import (
    ResourceProviderExecutor,
    ResourceProviderPayload,
)
from localstack.services.opensearch.cfn_resources import OpenSearchServiceDomainAllProperties
from localstack.services.ssm.cfn_resources import SSMParameterAllProperties
from localstack.utils.strings import short_uid


@pytest.mark.skip(reason="This is an example")
def test_ssm_deploy(aws_client, aws_client_factory):
    stack_name = f"stack-{short_uid()}"
    stack_id = f"arn:aws:::cloudformation/{stack_name}"

    resource_type = "AWS::SSM::Parameter"

    executor = ResourceProviderExecutor(
        resource_type=resource_type, stack_name=stack_name, stack_id=stack_id
    )

    # definition from the template
    props = SSMParameterAllProperties(Type="String", Value=f"value-{short_uid()}")

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
        "action": "Add",
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

    deployed_resource = executor.deploy_loop(resource_provider_payload).resource_model

    res = aws_client.ssm.get_parameter(Name=deployed_resource.Name)
    assert res["Parameter"]["Value"] == deployed_resource.Value

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
            "resourceProperties": deployed_resource,
            "previousResourceProperties": None,
            "callerCredentials": creds,
            "providerCredentials": creds,
            "systemTags": {},
            "previousSystemTags": {},
            "stackTags": {},
            "previousStackTags": {},
        },
    }
    executor.deploy_loop(resource_provider_payload)


@pytest.mark.skip(reason="This is an example")
def test_opensearch_deploy(aws_client, aws_client_factory):
    stack_name = f"stack-{short_uid()}"
    stack_id = f"arn:aws:::cloudformation/{stack_name}"

    resource_type = "AWS::OpenSearchService::Domain"

    executor = ResourceProviderExecutor(
        resource_type=resource_type, stack_name=stack_name, stack_id=stack_id
    )

    # definition from the template
    props = OpenSearchServiceDomainAllProperties(DomainName=f"domain-{short_uid()}")

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
        "action": "Add",
        "requestData": {
            "logicalResourceId": "MyDomain",
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

    executor.deploy_loop(resource_provider_payload)

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

    executor.deploy_loop(resource_provider_payload)
