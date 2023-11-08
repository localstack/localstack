import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@pytest.mark.parametrize("attribute_name", ["TopicName", "TopicArn"])
@markers.aws.validated
def test_nested_getatt_ref(deploy_cfn_template, aws_client, attribute_name, snapshot):
    topic_name = f"test-topic-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_getatt_ref.yaml"
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


@markers.aws.validated
def test_sub_resolving(deploy_cfn_template, aws_client, snapshot):
    """
    Tests different cases for Fn::Sub resolving

    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-sub.html


    TODO: cover all supported functions for VarName / VarValue:
        Fn::Base64
        Fn::FindInMap
        Fn::GetAtt
        Fn::GetAZs
        Fn::If
        Fn::ImportValue
        Fn::Join
        Fn::Select
        Ref

    """
    topic_name = f"test-topic-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_sub_resovling.yaml"
        ),
        parameters={"MyParam": topic_name},
    )
    snapshot.match("outputs", deployment.outputs)
    topic_arn = deployment.outputs["MyTopicArn"]

    # Verify the parts in the Fn::Sub string are resolved correctly.
    sub_output = deployment.outputs["MyTopicSub"]
    param, ref, getatt_topicname, getatt_topicarn = sub_output.split("|")
    assert param == topic_name
    assert ref == topic_arn
    assert getatt_topicname == topic_name
    assert getatt_topicarn == topic_arn

    map_sub_output = deployment.outputs["MyTopicSubWithMap"]
    att_in_map, ref_in_map, static_in_map = map_sub_output.split("|")
    assert att_in_map == topic_name
    assert ref_in_map == topic_arn
    assert static_in_map == "something"

    # Verify resource was created
    topic_arns = [t["TopicArn"] for t in aws_client.sns.list_topics()["Topics"]]
    assert topic_arn in topic_arns


@markers.aws.only_localstack
def test_unexisting_resource_dependency(deploy_cfn_template, aws_client):
    stack_name = f"s-{short_uid()}"

    with pytest.raises(Exception):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "../../../templates/cfn_unexisting_resource_dependency.yml",
            ),
            stack_name=stack_name,
        )

    description = aws_client.cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert description["StackStatus"] == "CREATE_FAILED"
    assert "Resource 'UnexistingResource' not found in stack" in description["StackStatusReason"]
