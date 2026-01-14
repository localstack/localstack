import json

from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@skip_if_legacy_engine()
@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..PhysicalResourceId"])
def test_requires_replacement(
    deploy_cfn_template,
    capture_per_resource_events,
    snapshot,
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    t1 = {
        "Resources": {
            "MyQueue": {
                "Type": "AWS::SQS::Queue",
            },
        },
        "Outputs": {
            "QueueName": {
                "Value": {"Fn::GetAtt": ["MyQueue", "QueueName"]},
            },
        },
    }
    t2 = {
        "Parameters": {
            "QueueName": {
                "Type": "String",
            },
        },
        "Resources": {
            "MyQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": {"Ref": "QueueName"},
                },
            },
        },
        "Outputs": {
            "QueueName": {
                "Value": {"Fn::GetAtt": ["MyQueue", "QueueName"]},
            },
        },
    }

    deploy_result = deploy_cfn_template(template=json.dumps(t1))
    given_queue_name = deploy_result.outputs["QueueName"]
    snapshot.add_transformer(snapshot.transform.regex(given_queue_name, "<queue-name-1>"))

    new_queue_name = f"queue-{short_uid()}"
    deploy_result_2 = deploy_cfn_template(
        template=json.dumps(t2),
        is_update=True,
        stack_name=deploy_result.stack_id,
        parameters={"QueueName": new_queue_name},
    )

    assert deploy_result_2.outputs["QueueName"] == new_queue_name
    assert given_queue_name != new_queue_name

    per_resource_events = capture_per_resource_events(
        deploy_result.stack_id,
    )
    snapshot.match("queue-events", per_resource_events["MyQueue"])
