import os

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.skip_offline
@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..DomainStatus.AdvancedSecurityOptions.AnonymousAuthEnabled",
        "$..DomainStatus.AutoTuneOptions.State",
        "$..DomainStatus.ChangeProgressDetails",
        "$..DomainStatus.DomainProcessingStatus",
        "$..DomainStatus.EBSOptions.VolumeSize",
        "$..DomainStatus.ElasticsearchClusterConfig.DedicatedMasterCount",
        "$..DomainStatus.ElasticsearchClusterConfig.InstanceCount",
        "$..DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessConfig",
        "$..DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled",
        "$..DomainStatus.Endpoint",
        "$..DomainStatus.ModifyingProperties",
        "$..DomainStatus.Processing",
        "$..DomainStatus.ServiceSoftwareOptions.CurrentVersion",
    ]
)
def test_cfn_handle_elasticsearch_domain(deploy_cfn_template, aws_client, snapshot):
    domain_name = f"es-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/elasticsearch_domain.yml"
    )

    deploy_cfn_template(template_path=template_path, parameters={"DomainName": domain_name})

    rs = aws_client.es.describe_elasticsearch_domain(DomainName=domain_name)
    status = rs["DomainStatus"]
    snapshot.match("domain", rs)

    tags = aws_client.es.list_tags(ARN=status["ARN"])["TagList"]
    snapshot.match("tags", tags)

    snapshot.add_transformer(snapshot.transform.key_value("DomainName"))
    snapshot.add_transformer(snapshot.transform.key_value("Endpoint"))
    snapshot.add_transformer(snapshot.transform.key_value("TLSSecurityPolicy"))
    snapshot.add_transformer(snapshot.transform.key_value("CurrentVersion"))
    snapshot.add_transformer(snapshot.transform.key_value("Description"))
