import pytest

from localstack.utils.strings import short_uid

TEST_TEMPLATE_10 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  DomainName:
    Type: String
    Default: dev
Resources:
  MyElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: !Ref "DomainName"
      ElasticsearchClusterConfig:
        InstanceCount: "1"
        InstanceType: 'm5.large.elasticsearch'
        ZoneAwarenessEnabled: false
        # remaining required attributes (DedicatedMasterType, WarmType) should get filled in by template deployer
      Tags:
        - Key: k1
          Value: v1
        - Key: k2
          Value: v2
Outputs:
  MyElasticsearchDomainEndpoint:
    Value: !GetAtt MyElasticsearchDomain.DomainEndpoint

  MyElasticsearchArn:
    Value: !GetAtt MyElasticsearchDomain.Arn

  MyElasticsearchDomainArn:
    Value: !GetAtt MyElasticsearchDomain.DomainArn

  MyElasticsearchRef:
    Value: !Ref MyElasticsearchDomain
"""


@pytest.mark.skip_offline
def test_cfn_handle_elasticsearch_domain(es_client, deploy_cfn_template):
    domain_name = f"es-{short_uid()}"

    stack = deploy_cfn_template(template=TEST_TEMPLATE_10, parameters={"DomainName": domain_name})
    assert len(stack.outputs) == 4

    rs = es_client.describe_elasticsearch_domain(DomainName=domain_name)
    status = rs["DomainStatus"]
    assert status["DomainName"] == domain_name
    assert stack.outputs["MyElasticsearchArn"] == status["ARN"]
    assert stack.outputs["MyElasticsearchDomainArn"] == status["ARN"]
    assert stack.outputs["MyElasticsearchDomainEndpoint"] == status["Endpoint"]
    assert stack.outputs["MyElasticsearchRef"] == status["DomainName"]

    tags = es_client.list_tags(ARN=status["ARN"])["TagList"]
    assert tags == [{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}]
