import json

import pytest

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers


@pytest.mark.skipif(not is_aws_cloud(), reason="Test only works on AWS")
@markers.aws.unknown
def test_cloudtrail_trace_example(
    cfn_store_events_role_arn, aws_client: ServiceLevelClientFactory, deploy_cfn_template
):
    """
    Example test to demonstrate capturing CloudFormation events using CloudTrail.
    """
    template = json.dumps(
        {
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                },
            },
            "Outputs": {
                "TopicArn": {
                    "Value": {
                        "Fn::GetAtt": ["MyTopic", "TopicArn"],
                    }
                }
            },
        }
    )

    stack = deploy_cfn_template(template=template, role_arn=cfn_store_events_role_arn)

    # perform normal test assertions here
    # no exception means the test succeeded
    aws_client.sns.get_topic_attributes(TopicArn=stack.outputs["TopicArn"])
