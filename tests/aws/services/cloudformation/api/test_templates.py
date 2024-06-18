import contextlib
import os
import textwrap

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import load_file
from localstack.utils.strings import short_uid, to_bytes


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..ResourceIdentifierSummaries..ResourceIdentifiers"]
)
def test_get_template_summary(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.sns_api())

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            # This template has no parameters, and so shows the issue
            os.path.dirname(__file__),
            "../../../templates/sns_topic_simple.yaml",
        )
    )

    res = aws_client.cloudformation.get_template_summary(StackName=deployment.stack_name)

    snapshot.match("template-summary", res)


@markers.aws.validated
@pytest.mark.parametrize("url_style", ["s3_url", "http_path", "http_host", "http_invalid"])
def test_create_stack_from_s3_template_url(
    url_style, snapshot, s3_create_bucket, aws_client, cleanups
):
    topic_name = f"topic-{short_uid()}"
    bucket_name = s3_create_bucket()
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic_name>"))
    snapshot.add_transformer(snapshot.transform.regex(bucket_name, "<bucket_name>"))

    stack_name = f"s-{short_uid()}"
    template = textwrap.dedent(
        """
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      TopicName:
        Type: String
    Resources:
      topic123:
        Type: AWS::SNS::Topic
        Properties:
          TopicName: !Ref TopicName
    """
    )

    aws_client.s3.put_object(Bucket=bucket_name, Key="test/template.yml", Body=to_bytes(template))

    match url_style:
        case "s3_url":
            template_url = f"s3://{bucket_name}/test/template.yml"
        case "http_path":
            template_url = f"https://s3.amazonaws.com/{bucket_name}/test/template.yml"
        case "http_host":
            template_url = f"https://{bucket_name}.s3.amazonaws.com/test/template.yml"
        case "http_invalid":
            # note: using an invalid (non-existing) URL here, but in fact all non-S3 HTTP URLs are invalid in real AWS
            template_url = "https://example.com/dummy.yml"
        case _:
            raise Exception(f"Unexpected `url_style` parameter: {url_style}")

    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

    # deploy stack
    error_expected = url_style in ["s3_url", "http_invalid"]
    context_manager = pytest.raises(ClientError) if error_expected else contextlib.nullcontext()
    with context_manager as ctx:
        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateURL=template_url,
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": topic_name}],
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

    # assert that either error was raised, or topic has been created
    if error_expected:
        snapshot.match("create-error", ctx.value.response)
    else:
        results = list(aws_client.sns.get_paginator("list_topics").paginate())
        matching = [
            t for res in results for t in res["Topics"] if t["TopicArn"].endswith(topic_name)
        ]
        snapshot.match("matching-topic", matching)


@markers.aws.validated
def test_validate_template(aws_client, snapshot):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/valid_template.json")
    )

    resp = aws_client.cloudformation.validate_template(TemplateBody=template)
    snapshot.match("validate-template", resp)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Error..Message"])
def test_validate_invalid_json_template_should_fail(aws_client, snapshot):
    invalid_json = '{"this is invalid JSON"="bobbins"}'

    with pytest.raises(ClientError) as ctx:
        aws_client.cloudformation.validate_template(TemplateBody=invalid_json)

    snapshot.match("validate-invalid-json", ctx.value.response)
