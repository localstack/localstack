import os

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.validated
def test_create_record_set_via_id(route53_hosted_zone, deploy_cfn_template):
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


@markers.aws.validated
def test_create_record_set_via_name(deploy_cfn_template, route53_hosted_zone):
    create_zone_response = route53_hosted_zone()
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/route53_hostedzonename_template.yaml"
        ),
        parameters=parameters,
    )


@markers.aws.validated
def test_create_record_set_without_resource_record(deploy_cfn_template, route53_hosted_zone):
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


@markers.aws.unknown
def test_created_hosted_zone_with_name(deploy_cfn_template, aws_client):
    route53_name = f"www.{short_uid()}.com."
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_hostedzonename_no_records_template.yaml",
        ),
        parameters=parameters,
    )
    response = aws_client.route53.list_hosted_zones_by_name(DNSName=route53_name)
    assert response["HostedZones"][0]["Name"] == route53_name


@markers.aws.unknown
def test_delete_hosted_zone_with_name(deploy_cfn_template, aws_client):
    route53_name = f"www.{short_uid()}.com."
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/route53_hostedzonename_no_records_template.yaml",
        ),
        parameters=parameters,
    )
    stack.destroy()
    response = aws_client.route53.list_hosted_zones_by_name(DNSName=route53_name)
    assert len(response["HostedZones"]) == 0
