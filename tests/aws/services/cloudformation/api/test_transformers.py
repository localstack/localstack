import json
import os
import textwrap
from dataclasses import dataclass

import pytest
from botocore.exceptions import WaiterError
from localstack_snapshot.snapshots.transformer import SortingTransformer
from tests.aws.services.cloudformation.conftest import skip_if_v1_provider, skipped_v2_items

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers
from localstack.utils.functions import call_safe
from localstack.utils.strings import short_uid, to_bytes


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..tags"])
def test_duplicate_resources(deploy_cfn_template, s3_bucket, snapshot, aws_client):
    snapshot.add_transformers_list(
        [
            *snapshot.transform.apigateway_api(),
            snapshot.transform.key_value("aws:cloudformation:stack-id"),
            snapshot.transform.key_value("aws:cloudformation:stack-name"),
        ]
    )

    # put API spec to S3
    api_spec = """
    swagger: 2.0
    info:
      version: "1.2.3"
      title: "Test API"
    basePath: /base
    """
    aws_client.s3.put_object(Bucket=s3_bucket, Key="api.yaml", Body=to_bytes(api_spec))

    # deploy template
    api_name = f"api-{short_uid()}"
    result = deploy_cfn_template(
        parameters={"ApiName": api_name, "BucketName": s3_bucket},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_apigw_with_include_fn.yml"
        ),
    )

    # assert REST API is created properly
    api_id = result.outputs.get("RestApiId")
    result = aws_client.apigateway.get_rest_api(restApiId=api_id)
    assert result
    snapshot.match("api-details", result)

    resources = aws_client.apigateway.get_resources(restApiId=api_id)
    snapshot.match("api-resources", resources)


@skip_if_v1_provider(reason="update not supported in v1")
@markers.aws.validated
def test_redeployment_with_fn_include(deploy_cfn_template, s3_bucket, snapshot, aws_client):
    snapshot.add_transformers_list(
        [
            *snapshot.transform.apigateway_api(),
            snapshot.transform.key_value("aws:cloudformation:stack-id"),
            snapshot.transform.key_value("aws:cloudformation:stack-name"),
        ]
    )

    # put API spec to S3
    api_spec = """
    swagger: 2.0
    info:
      version: "1.2.3"
      title: "Test API"
    basePath: /base
    """
    aws_client.s3.put_object(Bucket=s3_bucket, Key="api.yaml", Body=to_bytes(api_spec))

    # deploy template
    api_name = f"api-{short_uid()}"
    result = deploy_cfn_template(
        parameters={"ApiName": api_name, "BucketName": s3_bucket},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_apigw_with_include_fn.yml"
        ),
    )

    api_name = f"api-{short_uid()}"
    updated_result = deploy_cfn_template(
        stack_name=result.stack_name,
        is_update=True,
        parameters={"ApiName": api_name, "BucketName": s3_bucket},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_apigw_with_include_fn.yml"
        ),
    )

    api_id = updated_result.outputs.get("RestApiId")
    api = aws_client.apigateway.get_rest_api(restApiId=api_id)
    snapshot.match("api-details", api)


@markers.aws.validated
def test_transformer_property_level(deploy_cfn_template, s3_bucket, aws_client, snapshot):
    api_spec = textwrap.dedent("""
    Value: from_transformation
    """)
    aws_client.s3.put_object(Bucket=s3_bucket, Key="data.yaml", Body=to_bytes(api_spec))

    # deploy template
    template = textwrap.dedent("""
        Parameters:
          BucketName:
            Type: String
        Resources:
          MyParameter:
            Type: AWS::SSM::Parameter
            Properties:
              Description: hello
              Type: String
              "Fn::Transform":
                Name: "AWS::Include"
                Parameters:
                  Location: !Sub "s3://${BucketName}/data.yaml"
        Outputs:
          ParameterName:
            Value: !Ref MyParameter
        """)

    result = deploy_cfn_template(template=template, parameters={"BucketName": s3_bucket})
    param_name = result.outputs["ParameterName"]
    param = aws_client.ssm.get_parameter(Name=param_name)
    assert (
        param["Parameter"]["Value"] == "from_transformation"
    )  # value coming from the transformation
    describe_result = (
        aws_client.ssm.get_paginator("describe_parameters")
        .paginate(Filters=[{"Key": "Name", "Values": [param_name]}])
        .build_full_result()
    )
    assert (
        describe_result["Parameters"][0]["Description"] == "hello"
    )  # value from a property on the same level as the transformation

    original_template = aws_client.cloudformation.get_template(
        StackName=result.stack_id, TemplateStage="Original"
    )
    snapshot.match("original_template", original_template)
    processed_template = aws_client.cloudformation.get_template(
        StackName=result.stack_id, TemplateStage="Processed"
    )
    snapshot.match("processed_template", processed_template)


@markers.aws.validated
def test_transformer_individual_resource_level(deploy_cfn_template, s3_bucket, aws_client):
    api_spec = textwrap.dedent("""
    Type: AWS::SNS::Topic
    """)
    aws_client.s3.put_object(Bucket=s3_bucket, Key="data.yaml", Body=to_bytes(api_spec))

    # deploy template
    template = textwrap.dedent("""
        Parameters:
          BucketName:
            Type: String
        Resources:
          MyResource:
            "Fn::Transform":
                Name: "AWS::Include"
                Parameters:
                  Location: !Sub "s3://${BucketName}/data.yaml"
        Outputs:
          ResourceRef:
            Value: !Ref MyResource
        """)

    result = deploy_cfn_template(template=template, parameters={"BucketName": s3_bucket})
    resource_ref = result.outputs["ResourceRef"]
    # just checking that this doens't fail, i.e. the topic exists
    aws_client.sns.get_topic_attributes(TopicArn=resource_ref)


@dataclass
class TransformResult:
    stack_id: str
    template: dict


@pytest.fixture
def transform_template(aws_client: ServiceLevelClientFactory, snapshot, cleanups):
    stack_ids: list[str] = []

    def transform(template: str, parameters: dict[str, str] | None = None) -> TransformResult:
        stack_name = f"stack-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(stack_name, "<stack-name>"))

        parameters = [
            {"ParameterKey": key, "ParameterValue": value}
            for key, value in (parameters or {}).items()
        ]
        stack = aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Capabilities=["CAPABILITY_AUTO_EXPAND"],
            Parameters=parameters,
        )
        stack_id = stack["StackId"]
        stack_ids.append(stack_id)
        try:
            aws_client.cloudformation.get_waiter("stack_create_complete").wait(
                StackName=stack_id,
            )
        except WaiterError as e:
            events = aws_client.cloudformation.describe_stack_events(StackName=stack_id)[
                "StackEvents"
            ]
            relevant_fields = [
                {
                    key: event.get(key)
                    for key in [
                        "LogicalResourceId",
                        "ResourceType",
                        "ResourceStatus",
                        "ResourceStatusReason",
                    ]
                }
                for event in events
            ]
            raise RuntimeError(json.dumps(relevant_fields, indent=2, default=repr)) from e

        stack_resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_id)
        snapshot.match("resources", stack_resources)

        template = aws_client.cloudformation.get_template(
            StackName=stack_id, TemplateStage="Processed"
        )["TemplateBody"]
        return TransformResult(template=template, stack_id=stack_id)

    yield transform

    for stack_id in stack_ids:
        call_safe(lambda: aws_client.cloudformation.delete_stack(StackName=stack_id))


class TestLanguageExtensionsTransform:
    """
    Manual testing of the language extensions trasnform
    """

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..PhysicalResourceId", "$..StackId"])
    def test_transform_length(self, transform_template, snapshot):
        with open(
            os.path.realpath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../templates/cfn_languageextensions_length.yml",
                )
            )
        ) as infile:
            parameters = {"QueueList": "a,b,c"}
            transformed_template_result = transform_template(infile.read(), parameters)

        snapshot.match("transformed", transformed_template_result.template)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..PhysicalResourceId", "$..StackId"])
    def test_transform_foreach(self, transform_template, snapshot):
        topic_names = [
            f"mytopic1{short_uid()}",
            f"mytopic2{short_uid()}",
            f"mytopic3{short_uid()}",
        ]
        for i, name in enumerate(topic_names):
            snapshot.add_transformer(snapshot.transform.regex(name, f"<topic-name-{i}>"))

        with open(
            os.path.realpath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../templates/cfn_languageextensions_foreach.yml",
                )
            )
        ) as infile:
            transform_result = transform_template(
                infile.read(),
                parameters={
                    "pRepoARNs": ",".join(topic_names),
                },
            )
        snapshot.match("transformed", transform_result.template)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..StackResources..PhysicalResourceId", "$..StackResources..StackId"]
    )
    def test_transform_foreach_multiple_resources(self, transform_template, snapshot):
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda resource: resource["LogicalResourceId"])
        )
        with open(
            os.path.realpath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../templates/cfn_languageextensions_foreach_multiple_resources.yml",
                )
            )
        ) as infile:
            transform_result = transform_template(infile.read())
        snapshot.match("transformed", transform_result.template)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..DependsOn",
            # skipped due to a big in the provider not rendering the template correctly
            "$..Resources.GraphQLApi.Properties.Name",
            "$..OutputValue",
            "$..StackResources..PhysicalResourceId",
            "$..StackResources..StackId",
        ]
        + skipped_v2_items(
            # we now set this with the v2 provider for extra clarity but this field is not set on
            # AWS
            "$..StackResources..ResourceStatusReason",
        )
    )
    def test_transform_foreach_use_case(self, aws_client, transform_template, snapshot):
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda resource: resource["LogicalResourceId"])
        )
        event_names = ["Event1", "Event2"]
        server_event_names = ["ServerEvent1", "ServerEvent2"]
        for i, name in enumerate(event_names + server_event_names):
            snapshot.add_transformer(snapshot.transform.regex(name, f"<event-name-{i}>"))

        parameters = {
            "AppSyncSubscriptionFilterNames": ",".join(event_names),
            "AppSyncServerEventNames": ",".join(server_event_names),
        }
        with open(
            os.path.realpath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../templates/cfn_languageextensions_ryanair.yml",
                )
            )
        ) as infile:
            transform_result = transform_template(
                infile.read(),
                parameters=parameters,
            )
        snapshot.match("transformed", transform_result.template)

        # check that the resources have been created correctly
        outputs = aws_client.cloudformation.describe_stacks(StackName=transform_result.stack_id)[
            "Stacks"
        ][0]["Outputs"]
        snapshot.match("stack-outputs", outputs)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..StackResources..PhysicalResourceId",
            "$..StackResources..StackId",
        ]
    )
    def test_transform_to_json_string(self, aws_client, transform_template, snapshot):
        snapshot.add_transformer(
            SortingTransformer("StackResources", lambda resource: resource["LogicalResourceId"])
        )
        with open(
            os.path.realpath(
                os.path.join(
                    os.path.dirname(__file__),
                    "../../../templates/cfn_languageextensions_tojsonstring.yml",
                )
            )
        ) as infile:
            transform_result = transform_template(infile.read())
        snapshot.match("transformed", transform_result.template)

        outputs = aws_client.cloudformation.describe_stacks(StackName=transform_result.stack_id)[
            "Stacks"
        ][0]["Outputs"]
        outputs = {every["OutputKey"]: every["OutputValue"] for every in outputs}

        object_value = aws_client.ssm.get_parameter(Name=outputs["ObjectName"])["Parameter"][
            "Value"
        ]
        snapshot.match("object-value", object_value)
        array_value = aws_client.ssm.get_parameter(Name=outputs["ArrayName"])["Parameter"]["Value"]
        snapshot.match("array-value", array_value)
