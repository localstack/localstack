import os

import pytest

from localstack.utils.strings import short_uid


@pytest.mark.aws_validated
def test_domain(deploy_cfn_template, opensearch_client, cfn_client, snapshot):
    # snapshot.add_transformer(snapshot.transform.resource_name())
    # snapshot.add_transformer(snapshot.transform.key_value("Name", "trigger-name"))
    # snapshot.add_transformer(snapshot.transform.cloudformation_api())

    name = f"domain-{short_uid()}"

    template_path = os.path.join(os.path.dirname(__file__), "../templates/opensearch_domain.yml")
    stack = deploy_cfn_template(
        template_path=template_path,
        parameters={"domainName": name},
    )
    snapshot.match("stack_outputs", stack.outputs)

    description = cfn_client.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("stack_resource_description", description["StackResources"])

    domain = opensearch_client.describe_domain(DomainName=name)
    snapshot.match("domain", domain["DomainStatus"])
