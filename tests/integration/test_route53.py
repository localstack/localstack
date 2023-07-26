import pytest

from localstack.aws.accounts import get_aws_account_id
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


# TODO: add proper cleanup
class TestRoute53:
    def test_create_hosted_zone(self, aws_client):
        response = aws_client.route53.create_hosted_zone(Name="zone123", CallerReference="ref123")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201

        response = aws_client.route53.get_change(Id="string")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_crud_health_check(self, aws_client):
        response = aws_client.route53.create_health_check(
            CallerReference="test123",
            HealthCheckConfig={
                "IPAddress": "10.0.0.25",
                "Port": 80,
                "Type": "HTTP",
                "ResourcePath": "/",
                "FullyQualifiedDomainName": "example.com",
                "SearchString": "a good response",
                "RequestInterval": 10,
                "FailureThreshold": 2,
            },
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201
        health_check_id = response["HealthCheck"]["Id"]
        response = aws_client.route53.get_health_check(HealthCheckId=health_check_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert response["HealthCheck"]["Id"] == health_check_id
        response = aws_client.route53.delete_health_check(HealthCheckId=health_check_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        with pytest.raises(Exception) as ctx:
            aws_client.route53.delete_health_check(HealthCheckId=health_check_id)
        assert "NoSuchHealthCheck" in str(ctx.value)

    def test_associate_vpc_with_hosted_zone(self, cleanups, aws_client):
        name = "zone123"
        response = aws_client.route53.create_hosted_zone(
            Name=name,
            CallerReference="ref123",
            HostedZoneConfig={"PrivateZone": True, "Comment": "test"},
        )
        zone_id = response["HostedZone"]["Id"]
        zone_id = zone_id.replace("/hostedzone/", "")

        # create VPCs
        vpc1 = aws_client.ec2.create_vpc(CidrBlock="10.113.0.0/24")
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc1["Vpc"]["VpcId"]))
        vpc1_id = vpc1["Vpc"]["VpcId"]
        vpc2 = aws_client.ec2.create_vpc(CidrBlock="10.114.0.0/24")
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc2["Vpc"]["VpcId"]))
        vpc2_id = vpc2["Vpc"]["VpcId"]

        # associate zone with VPC
        vpc_region = aws_stack.get_region()
        for vpc_id in [vpc1_id, vpc2_id]:
            result = aws_client.route53.associate_vpc_with_hosted_zone(
                HostedZoneId=zone_id,
                VPC={"VPCRegion": vpc_region, "VPCId": vpc_id},
                Comment="test 123",
            )
            assert result["ChangeInfo"].get("Id")

        cleanups.append(
            lambda: aws_client.route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id, VPC={"VPCRegion": vpc_region, "VPCId": vpc1_id}
            )
        )

        # list zones by VPC
        result = aws_client.route53.list_hosted_zones_by_vpc(VPCId=vpc1_id, VPCRegion=vpc_region)[
            "HostedZoneSummaries"
        ]
        expected = {
            "HostedZoneId": zone_id,
            "Name": "%s." % name,
            "Owner": {"OwningAccount": get_aws_account_id()},
        }
        assert expected in result

        # list zones by name
        result = aws_client.route53.list_hosted_zones_by_name(DNSName=name).get("HostedZones")
        assert result[0]["Name"] == "zone123."
        result = aws_client.route53.list_hosted_zones_by_name(DNSName="%s." % name).get(
            "HostedZones"
        )
        assert result[0]["Name"] == "zone123."

        # assert that VPC is attached in Zone response
        result = aws_client.route53.get_hosted_zone(Id=zone_id)
        for vpc_id in [vpc1_id, vpc2_id]:
            assert {"VPCRegion": vpc_region, "VPCId": vpc_id} in result["VPCs"]

        # disassociate
        aws_client.route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id,
            VPC={"VPCRegion": vpc_region, "VPCId": vpc2_id},
            Comment="test2",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] in [200, 201]
        # subsequent call (after disassociation) should fail with 404 error
        with pytest.raises(Exception):
            aws_client.route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id,
                VPC={"VPCRegion": vpc_region, "VPCId": vpc2_id},
            )

    def test_reusable_delegation_sets(self, aws_client):
        client = aws_client.route53

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
        assert "NoSuchDelegationSet" in str(ctx.value)
