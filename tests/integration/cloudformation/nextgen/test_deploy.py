import logging
import time
import uuid

import pytest

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ResourceProviderExecutor,
    ResourceProviderPayload,
)
from localstack.services.opensearch.cfn_resources import OpenSearchServiceDomainAllProperties
from localstack.services.ssm.cfn_resources import SSMParameterAllProperties
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


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

    for i in range(30):
        event = executor.execute_action(resource_provider_payload)
        if event.status == OperationStatus.SUCCESS:
            LOG.debug(f"took {i + 1} loop iterations to deploy")
            break
        time.sleep(5)
    else:
        # we did not break the loop, so consider a timeout error here
        raise RuntimeError("Could not deploy resource")

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
