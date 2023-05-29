from typing import TypeVar

import pytest

from localstack.services.opensearch.resource_providers.domain import OpenSearchDomainAllProperties
from localstack.services.sqs.resource_providers.queue import SQSQueueAllProperties
from localstack.services.ssm.resource_providers.parameter import SSMParameterAllProperties
from localstack.utils.strings import short_uid

Properties = TypeVar("Properties")


@pytest.mark.parametrize(
    "type_name,props",
    [
        (
            "AWS::OpenSearchService::Domain",
            OpenSearchDomainAllProperties(DomainName=f"domain-{short_uid()}"),
        ),
        (
            "AWS::SSM::Parameter",
            SSMParameterAllProperties(Type="String", Value=f"value-{short_uid()}"),
        ),
        (
            "AWS::SQS::Queue",
            SQSQueueAllProperties(
                QueueName=f"queue-{short_uid()}.fifo",
                FifoQueue=True,
                VisibilityTimeout=10,
                RedrivePolicy={
                    "deadLetterTargetArn": "arn:aws:sqs:us-east-1:123456789012:my-dead-letter-queue",
                    "maxReceiveCount": 5,
                },
            ),
        ),
        # TODO: Add your resource definitions here!
    ],
    ids=[
        "opensearch-domain",
        "ssm-parameter",
        "sqs-queue",
    ],
)
@pytest.mark.skip(reason="Example")
def test_roundtrip(type_name, props, perform_cfn_operation):
    # deploy
    event = perform_cfn_operation(
        logical_resource_id="MyResource",
        resource_type=type_name,
        action="Add",
        resource_props=props,
    )

    # delete
    perform_cfn_operation(
        logical_resource_id="MyResource",
        resource_type=type_name,
        action="Remove",
        resource_props=event.resource_model,
    )
