from localstack.utils.common import short_uid

TEST_TEMPLATE = """
Resources:
  cert1:
    Type: "AWS::CertificateManager::Certificate"
    Properties:
      DomainName: "{{domain}}"
      DomainValidationOptions:
        - DomainName: "{{domain}}"
          HostedZoneId: zone123  # using dummy ID for now
      ValidationMethod: DNS
"""


def test_cfn_apigateway_aws_integration(
    deploy_cfn_template,
    acm_client,
):
    domain = f"domain-{short_uid()}.com"
    deploy_cfn_template(TEST_TEMPLATE, domain=domain)

    result = acm_client.list_certificates()["CertificateSummaryList"]
    result = [cert for cert in result if cert["DomainName"] == domain]
    assert result
