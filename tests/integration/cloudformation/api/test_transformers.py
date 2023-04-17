import pytest

from localstack.utils.strings import short_uid, to_bytes


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..tags"])
def test_duplicate_resources(deploy_cfn_template, s3_bucket, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.key_value("id"))
    snapshot.add_transformer(snapshot.transform.key_value("name"))
    snapshot.add_transformer(snapshot.transform.key_value("aws:cloudformation:stack-id"))
    snapshot.add_transformer(snapshot.transform.key_value("aws:cloudformation:stack-name"))

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
