import os

import pytest

from localstack.testing.pytest import markers


@pytest.fixture
def record_set_transformers(snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.jsonpath(
                "$..ResourceRecords..Value.[*]", value_replacement="resource-record"
            ),
            snapshot.transform.jsonpath(
                "$..ResourceRecordSets..Name", value_replacement="record-name"
            ),
        ]
    )


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_via_id(
    route53_hosted_zone, aws_client, deploy_cfn_template, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/route53_hostedzoneid_template.yaml"
        ),
        parameters=parameters,
        max_wait=300,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_via_name(
    deploy_cfn_template, aws_client, route53_hosted_zone, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/route53_hostedzonename_template.yaml"
        ),
        parameters=parameters,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(
        HostedZoneId=create_zone_response["HostedZone"]["Id"]
    )
    snapshot.match("record-sets", rr_sets)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # Moto returns a different value (300 instead of 100) when not provided
        "$..MaxItems",
        # Different hardcoded value in the SOA record compared to Amazon
        "$..ResourceRecordSets.[2].ResourceRecords.[0].Value",
    ]
)
def test_create_record_set_without_resource_record(
    deploy_cfn_template, aws_client, route53_hosted_zone, snapshot, record_set_transformers
):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_recordset_without_resource_records.yaml",
        ),
        parameters=parameters,
    )
    rr_sets = aws_client.route53.list_resource_record_sets(HostedZoneId=hosted_zone_id)
    snapshot.match("record-sets", rr_sets)
