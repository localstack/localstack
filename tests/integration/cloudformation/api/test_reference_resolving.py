import os

import pytest

from localstack.utils.strings import short_uid


@pytest.mark.parametrize("attribute_name", ["TopicName", "TopicArn"])
@pytest.mark.aws_validated
def test_nested_getatt_ref(deploy_cfn_template, aws_client, attribute_name, snapshot):
    topic_name = f"test-topic-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/cfn-getatt-ref.yaml"
        ),
        parameters={"MyParam": topic_name, "CustomOutputName": attribute_name},
    )
    snapshot.match("outputs", deployment.outputs)
    topic_arn = deployment.outputs["MyTopicArn"]

    # Verify the nested GetAtt Ref resolved correctly
    custom_ref = deployment.outputs["MyTopicCustom"]
    if attribute_name == "TopicName":
        assert custom_ref == topic_name

    if attribute_name == "TopicArn":
        assert custom_ref == topic_arn

    # Verify resource was created
    topic_arns = [t["TopicArn"] for t in aws_client.sns.list_topics()["Topics"]]
    assert topic_arn in topic_arns
