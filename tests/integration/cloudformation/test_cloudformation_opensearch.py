import os

import pytest

from localstack.utils.strings import short_uid


# Domain deployment in AWS takes too much time
@pytest.mark.only_localstack
def test_domain(deploy_cfn_template, opensearch_client, cfn_client):
    name = f"domain-{short_uid()}"

    template_path = os.path.join(os.path.dirname(__file__), "../templates/opensearch_domain.yml")
    deploy_cfn_template(
        template_path=template_path,
        parameters={"domainName": name},
    )

    domain = opensearch_client.describe_domain(DomainName=name)
    assert domain["DomainStatus"]
