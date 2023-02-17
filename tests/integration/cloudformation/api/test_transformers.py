import pytest

from localstack.utils.strings import short_uid, to_bytes


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..tags"])
def test_duplicate_resources(
    deploy_cfn_template, s3_bucket, s3_client, apigateway_client, cfn_client, snapshot
):
    snapshot.add_transformer(snapshot.transform.key_value("id"))
    snapshot.add_transformer(snapshot.transform.key_value("name"))

    api_name = f"api-{short_uid()}"

    # put API spec to S3
    api_spec = """
    swagger: 2.0
    info:
      version: "1.2.3"
      title: "Test API"
    basePath: /base
    """
    s3_client.put_object(Bucket=s3_bucket, Key="api.yaml", Body=to_bytes(api_spec))

    # deploy template
    template = f"""
    Resources:
      RestApi:
        Type: AWS::ApiGateway::RestApi
        Properties:
          Name: {api_name}
          Body:
            'Fn::Transform':
              Name: 'AWS::Include'
              Parameters:
                Location: s3://{s3_bucket}/api.yaml
    """
    deploy_cfn_template(template=template)

    # assert REST API is created properly
    result = apigateway_client.get_rest_apis()
    matching = [api for api in result["items"] if api["name"] == api_name]
    assert matching
    snapshot.match("api-details", matching)
