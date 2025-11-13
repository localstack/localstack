import contextlib
import json
import os
import textwrap

import pytest
from botocore.exceptions import ClientError
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import StackDeployError
from localstack.utils.common import load_file
from localstack.utils.strings import short_uid, to_bytes


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..ResourceIdentifierSummaries..ResourceIdentifiers", "$..Parameters"]
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
@skip_if_legacy_engine()
def test_get_template_summary_non_executed_change_set(aws_client, snapshot, cleanups):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template_body = {
        "Resources": {
            "MyParameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": short_uid(),
                },
            },
        },
    }
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=json.dumps(template_body),
        ChangeSetType="CREATE",
    )
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
        ChangeSetName=response["Id"]
    )
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=response["StackId"]))

    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template_summary(StackName=stack_name)

    snapshot.match("error", exc_info.value.response)


@markers.aws.validated
@skip_if_legacy_engine()
def test_get_template_summary_no_resources(aws_client, snapshot):
    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template_summary(TemplateBody="{}")
    snapshot.match("error", exc_info.value.response)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..ResourceIdentifierSummaries..ResourceIdentifiers"]
)
@skip_if_legacy_engine()
def test_get_template_summary_failed_stack(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template = {
        "Resources": {
            "MyParameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    # Note: missing Value parameter so the resource provider should fail
                },
            },
        },
    }

    stack_name = f"stack-{short_uid()}"
    with pytest.raises(StackDeployError):
        deploy_cfn_template(template=json.dumps(template), stack_name=stack_name)

    summary = aws_client.cloudformation.get_template_summary(StackName=stack_name)
    snapshot.match("template-summary", summary)


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
@markers.snapshot.skip_snapshot_verify(paths=["$..Parameters..DefaultValue"])
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


@skip_if_legacy_engine()
@markers.aws.validated
def test_get_template_no_arguments(aws_client, snapshot):
    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template()
    snapshot.match("stack-error", exc_info.value.response)


@markers.aws.validated
def test_get_template_missing_resources_stack(aws_client, snapshot):
    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template(StackName="does-not-exist")
    snapshot.match("stack-error", exc_info.value.response)


@skip_if_legacy_engine()
@markers.aws.validated
def test_get_template_missing_resources_change_set(aws_client, snapshot):
    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template(ChangeSetName="does-not-exist")
    snapshot.match("change-set-error", exc_info.value.response)


@skip_if_legacy_engine()
@markers.aws.validated
def test_get_template_missing_resources_change_set_id(aws_client, snapshot):
    change_set_id = (
        "arn:aws:cloudformation:us-east-1:000000000000:changeSet/change-set-926829fe/d065e78c"
    )
    snapshot.add_transformer(snapshot.transform.regex(change_set_id, "<change-set-id>"))
    with pytest.raises(ClientError) as exc_info:
        aws_client.cloudformation.get_template(ChangeSetName=change_set_id)
    snapshot.match("change-set-error", exc_info.value.response)


@markers.aws.validated
def test_create_stack_invalid_yaml_template_should_fail(aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    # add transformer to ignore the error location
    # TODO: add this information back in to improve the UX
    snapshot.add_transformer(snapshot.transform.regex(r"\s+\([^)]+\)", ""))

    stack_name = f"stack-{short_uid()}"
    invalid_yaml = textwrap.dedent(
        """\
        Resources:
          MyBucket:
            Type: AWS::S3::Bucket
            Properties:
                BucketName: test
              VersioningConfiguration:
                Status: Enabled
        """
    )

    with pytest.raises(ClientError) as ctx:
        aws_client.cloudformation.create_stack(StackName=stack_name, TemplateBody=invalid_yaml)

    snapshot.match("create-invalid-yaml", ctx.value.response)
