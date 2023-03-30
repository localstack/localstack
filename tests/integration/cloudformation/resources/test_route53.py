import os

import pytest


@pytest.mark.aws_validated
def test_create_record_set_via_id(route53_hosted_zone, deploy_cfn_template):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/route53_hostedzoneid_template.yaml"
        ),
        parameters=parameters,
        max_wait=300,
    )


def test_create_record_set_via_name(deploy_cfn_template, route53_hosted_zone):
    create_zone_response = route53_hosted_zone()
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneName": route53_name, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/route53_hostedzonename_template.yaml"
        ),
        parameters=parameters,
    )


def test_create_record_set_without_resource_record(deploy_cfn_template, route53_hosted_zone):
    create_zone_response = route53_hosted_zone()
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]
    route53_name = create_zone_response["HostedZone"]["Name"]
    parameters = {"HostedZoneId": hosted_zone_id, "Name": route53_name}
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../templates/route53_recordset_without_resource_records.yaml",
        ),
        parameters=parameters,
    )
