import copy
import json

import pytest

from localstack import config
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = pytest.mark.skipif(
    not is_aws_cloud() and config.SERVICE_PROVIDER_CONFIG["cloudformation"] == "engine-v2",
    reason="Only targeting the new engine",
)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..NotificationARNs",
        "$..Parameters",
        "$..Changes..ResourceChange.Details",
        "$..Changes..ResourceChange.Scope",
        "$..Changes..ResourceChange.PhysicalResourceId",
        "$..Changes..ResourceChange.Replacement",
    ]
)
def test_single_resource_static_update(aws_client: ServiceLevelClientFactory, snapshot, cleanups):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    parameter_name = f"parameter-{short_uid()}"
    value1 = "foo"
    value2 = "bar"

    t1 = {
        "Resources": {
            "MyParameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": parameter_name,
                    "Type": "String",
                    "Value": value1,
                },
            },
        },
    }

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"cs-{short_uid()}"
    cs_result = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=json.dumps(t1),
        ChangeSetType="CREATE",
    )
    cs_id = cs_result["Id"]
    stack_id = cs_result["StackId"]
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(ChangeSetName=cs_id)
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_id))

    describe_result = aws_client.cloudformation.describe_change_set(ChangeSetName=cs_id)
    snapshot.match("describe-1", describe_result)

    aws_client.cloudformation.execute_change_set(ChangeSetName=cs_id)
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_id)

    parameter = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("parameter-1", parameter)

    t2 = copy.deepcopy(t1)
    t2["Resources"]["MyParameter"]["Properties"]["Value"] = value2

    change_set_name = f"cs-{short_uid()}"
    cs_result = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=json.dumps(t2),
    )
    cs_id = cs_result["Id"]
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(ChangeSetName=cs_id)

    describe_result = aws_client.cloudformation.describe_change_set(ChangeSetName=cs_id)
    snapshot.match("describe-2", describe_result)

    aws_client.cloudformation.execute_change_set(ChangeSetName=cs_id)
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack_id)

    parameter = aws_client.ssm.get_parameter(Name=parameter_name)["Parameter"]
    snapshot.match("parameter-2", parameter)
