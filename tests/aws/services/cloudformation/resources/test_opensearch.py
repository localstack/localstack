import os

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..ClusterConfig.DedicatedMasterCount",  # added in LS
        "$..ClusterConfig.DedicatedMasterEnabled",  # added in LS
        "$..ClusterConfig.DedicatedMasterType",  # added in LS
        "$..SoftwareUpdateOptions",  # missing
        "$..OffPeakWindowOptions",  # missing
        "$..ChangeProgressDetails",  # missing
        "$..AutoTuneOptions.UseOffPeakWindow",  # missing
        "$..ClusterConfig.MultiAZWithStandbyEnabled",  # missing
        "$..AdvancedSecurityOptions.AnonymousAuthEnabled",  # missing
        # TODO different values:
        "$..Processing",
        "$..ServiceSoftwareOptions.CurrentVersion",
        "$..ClusterConfig.DedicatedMasterEnabled",
        "$..ClusterConfig.InstanceType",  # TODO the type was set in cfn
        "$..AutoTuneOptions.State",
        '$..AdvancedOptions."rest.action.multi.allow_explicit_index"',  # TODO this was set to false in cfn
    ]
)
def test_domain(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("DomainId"))
    snapshot.add_transformer(snapshot.transform.key_value("DomainName"))
    snapshot.add_transformer(snapshot.transform.key_value("ChangeId"))
    snapshot.add_transformer(snapshot.transform.key_value("Endpoint"), priority=-1)
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/opensearch_domain.yml"
    )
    result = deploy_cfn_template(template_path=template_path)
    domain_endpoint = result.outputs["SearchDomainEndpoint"]
    assert domain_endpoint
    domain_name = result.outputs["SearchDomain"]
    domain = aws_client.opensearch.describe_domain(DomainName=domain_name)
    assert domain["DomainStatus"]
    snapshot.match("describe_domain", domain)
