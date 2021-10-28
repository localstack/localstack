import unittest

from localstack import constants
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestRoute53(unittest.TestCase):
    def test_create_hosted_zone(self):
        route53 = aws_stack.connect_to_service("route53")

        response = route53.create_hosted_zone(Name="zone123", CallerReference="ref123")
        self.assertEqual(201, response["ResponseMetadata"]["HTTPStatusCode"])

        response = route53.get_change(Id="string")
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def test_associate_vpc_with_hosted_zone(self):
        ec2 = aws_stack.connect_to_service("ec2")
        route53 = aws_stack.connect_to_service("route53")

        name = "zone123"
        response = route53.create_hosted_zone(Name=name, CallerReference="ref123")
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
        self.assertTrue(result["ChangeInfo"].get("Id"))

        # list zones by VPC
        result = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=vpc_region)[
            "HostedZoneSummaries"
        ]
        expected = {
            "HostedZoneId": zone_id,
            "Name": "%s." % name,
            "Owner": {"OwningAccount": constants.TEST_AWS_ACCOUNT_ID},
        }
        self.assertIn(expected, result)

        # list zones by name
        result = route53.list_hosted_zones_by_name(DNSName=name).get("HostedZones")
        self.assertEqual("zone123.", result[0]["Name"])
        result = route53.list_hosted_zones_by_name(DNSName="%s." % name).get("HostedZones")
        self.assertEqual("zone123.", result[0]["Name"])

        result = route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id,
            VPC={"VPCRegion": aws_stack.get_region(), "VPCId": vpc_id},
            Comment="test2",
        )
        self.assertIn(response["ResponseMetadata"]["HTTPStatusCode"], [200, 201])
        # subsequent call (after disassociation) should fail with 404 error
        with self.assertRaises(Exception):
            route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id,
                VPC={"VPCRegion": aws_stack.get_region(), "VPCId": vpc_id},
            )

    def test_reusable_delegation_sets(self):
        client = aws_stack.connect_to_service("route53")

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
        self.assertEqual(200, result_1["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(set_id_1, result_1["DelegationSet"]["Id"])

        result_1 = client.list_reusable_delegation_sets()
        self.assertEqual(200, result_1["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(len(sets_before) + 2, len(result_1["DelegationSets"]))

        result_1 = client.delete_reusable_delegation_set(Id=set_id_1)
        self.assertEqual(200, result_1["ResponseMetadata"]["HTTPStatusCode"])

        result_2 = client.delete_reusable_delegation_set(Id=set_id_2)
        self.assertEqual(200, result_2["ResponseMetadata"]["HTTPStatusCode"])

        with self.assertRaises(Exception) as ctx:
            client.get_reusable_delegation_set(Id=set_id_1)
        self.assertEqual(404, ctx.exception.response["ResponseMetadata"]["HTTPStatusCode"])
