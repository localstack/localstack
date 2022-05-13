import os


def test_sqs_queue_policy(sqs_client, deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/sqs_with_queuepolicy.yaml"
        )
    )
    queue_url = result.outputs["QueueUrlOutput"]
    resp = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    assert (
        "Statement" in resp["Attributes"]["Policy"]
    )  # just kind of a smoke test to see if its set


def test_sqs_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        template_mapping={"is_fifo": "true"},
    )
    assert ".fifo" in result.outputs["FooQueueName"]


def test_sqs_non_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        template_mapping={"is_fifo": "false"},
    )
    assert ".fifo" not in result.outputs["FooQueueName"]
