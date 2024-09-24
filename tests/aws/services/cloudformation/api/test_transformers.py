import textwrap

from localstack.testing.pytest import markers
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
    template = """
    Parameters:
      ApiName:
        Type: String
      BucketName:
        Type: String
    Resources:
      RestApi:
        Type: AWS::ApiGateway::RestApi
        Properties:
          Name: !Ref ApiName
          Body:
            'Fn::Transform':
              Name: 'AWS::Include'
              Parameters:
                Location: !Sub "s3://${BucketName}/api.yaml"
    Outputs:
      RestApiId:
        Value: !Ref RestApi
    """

    api_name = f"api-{short_uid()}"
    result = deploy_cfn_template(
        template=template, parameters={"ApiName": api_name, "BucketName": s3_bucket}
    )

    # assert REST API is created properly
    api_id = result.outputs.get("RestApiId")
    result = aws_client.apigateway.get_rest_api(restApiId=api_id)
    assert result
    snapshot.match("api-details", result)

    resources = aws_client.apigateway.get_resources(restApiId=api_id)
    snapshot.match("api-resources", resources)


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
