import json
import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_topic_policy_modify(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "sns_topicpolicy_all_properties.yml")
    topic_arn = stack.outputs["TopicArn"]

    attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    policy = json.loads(attrs["Attributes"]["Policy"])
    snapshot.match("initial_policy_sid", {"Sid": policy["Statement"][0]["Sid"]})

    deploy_stack(
        deploy_cfn_template,
        "sns_topicpolicy_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
    policy = json.loads(attrs["Attributes"]["Policy"])
    snapshot.match("updated_policy_sid", {"Sid": policy["Statement"][0]["Sid"]})

    snapshot.add_transformer(snapshot.transform.regex(topic_arn, "<topic-arn>"))
