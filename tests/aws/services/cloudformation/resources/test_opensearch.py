import os

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.unknown
def test_domain(deploy_cfn_template, aws_client):
    name = f"domain-{short_uid()}"

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/opensearch_domain.yml"
    )
    deploy_cfn_template(
        template_path=template_path,
        parameters={"domainName": name},
    )

    domain = aws_client.opensearch.describe_domain(DomainName=name)
    assert domain["DomainStatus"]
