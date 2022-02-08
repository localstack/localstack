import re

import pytest

from localstack import constants
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestRoute53:
    def test_create_hosted_zone(self):
        route53 = aws_stack.create_external_boto_client("route53")

        response = route53.create_hosted_zone(Name="zone123", CallerReference="ref123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201

        response = route53.get_change(Id="string")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_associate_vpc_with_hosted_zone(self):
        ec2 = aws_stack.create_external_boto_client("ec2")
        route53 = aws_stack.create_external_boto_client("route53")

        name = "zone123"
        response = route53.create_hosted_zone(
            Name=name,
            CallerReference="ref123",
            HostedZoneConfig={"PrivateZone": True, "Comment": "test"},
        )
        zone_id = response["HostedZone"]["Id"]
        zone_id = zone_id.replace("/hostedzone/", "")

        # associate zone with VPC
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/24")
        vpc_id = vpc["Vpc"]["VpcId"]
        vpc_region = aws_stack.get_region()
        result = route53.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_id,
            VPC={"VPCRegion": vpc_region, "VPCId": vpc_id},
            Comment="test 123",
        )
        assert result["ChangeInfo"].get("Id")

        # list zones by VPC
        result = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=vpc_region)[
            "HostedZoneSummaries"
        ]
        expected = {
            "HostedZoneId": f"/hostedzone/{zone_id}",
            "Name": "%s." % name,
            "Owner": {"OwningAccount": constants.TEST_AWS_ACCOUNT_ID},
        }
        assert expected in result

        # list zones by name
        result = route53.list_hosted_zones_by_name(DNSName=name).get("HostedZones")
        assert result[0]["Name"] == "zone123."
        result = route53.list_hosted_zones_by_name(DNSName="%s." % name).get("HostedZones")
        assert result[0]["Name"] == "zone123."

        # assert that VPC is attached in Zone response
        result = route53.get_hosted_zone(Id=zone_id)
        assert result["VPCs"] == [{"VPCRegion": vpc_region, "VPCId": vpc_id}]

        # disassociate
        route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id,
            VPC={"VPCRegion": aws_stack.get_region(), "VPCId": vpc_id},
            Comment="test2",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] in [200, 201]
        # subsequent call (after disassociation) should fail with 404 error
        with pytest.raises(Exception):
            route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id,
                VPC={"VPCRegion": aws_stack.get_region(), "VPCId": vpc_id},
            )

    def test_reusable_delegation_sets(self):
        client = aws_stack.create_external_boto_client("route53")

        sets_before = client.list_reusable_delegation_sets().get("DelegationSets", [])

        call_ref_1 = "c-%s" % short_uid()
        result_1 = client.create_reusable_delegation_set(CallerReference=call_ref_1)[
            "DelegationSet"
        ]
        set_id_1 = result_1["Id"]

        call_ref_2 = "c-%s" % short_uid()
        result_2 = client.create_reusable_delegation_set(CallerReference=call_ref_2)[
            "DelegationSet"
        ]
        set_id_2 = result_2["Id"]

        result_1 = client.get_reusable_delegation_set(Id=set_id_1)
        assert result_1["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert result_1["DelegationSet"]["Id"] == set_id_1

        result_1 = client.list_reusable_delegation_sets()
        assert result_1["ResponseMetadata"]["HTTPStatusCode"] == 200
        # TODO: assertion should be updated, to allow for parallel tests
        assert len(result_1["DelegationSets"]) == len(sets_before) + 2

        result_1 = client.delete_reusable_delegation_set(Id=set_id_1)
        assert result_1["ResponseMetadata"]["HTTPStatusCode"] == 200

        result_2 = client.delete_reusable_delegation_set(Id=set_id_2)
        assert result_2["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(Exception) as ctx:
            client.get_reusable_delegation_set(Id=set_id_1)
        assert ctx.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400


class TestRoute53Resolver:
    def test_create_resolver_endpoint(self):
        ec2 = aws_stack.create_external_boto_client("ec2")
        resolver = aws_stack.create_external_boto_client("route53resolver")

        # getting list of existing (default) subnets
        subnets = ec2.describe_subnets()["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets]
        # construct IPs within CIDR range
        ips = [re.sub(r"(.*)\.[0-9]+/.+", r"\1.5", s["CidrBlock"]) for s in subnets]

        groups = []
        addresses = [
            {"SubnetId": subnet_ids[0], "Ip": ips[0]},
            {"SubnetId": subnet_ids[1], "Ip": ips[1]},
        ]

        result = resolver.create_resolver_endpoint(
            CreatorRequestId="req123",
            SecurityGroupIds=groups,
            Direction="INBOUND",
            IpAddresses=addresses,
        )
        result = result.get("ResolverEndpoint")
        assert result
        assert result.get("CreatorRequestId") == "req123"
        assert result.get("Direction") == "INBOUND"
