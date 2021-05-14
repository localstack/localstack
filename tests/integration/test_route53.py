import unittest
from localstack import constants
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestRoute53(unittest.TestCase):

    def test_create_hosted_zone(self):
        route53 = aws_stack.connect_to_service('route53')

        response = route53.create_hosted_zone(Name='zone123', CallerReference='ref123')
        self.assertEqual(201, response['ResponseMetadata']['HTTPStatusCode'])

        response = route53.get_change(Id='string')
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_associate_vpc_with_hosted_zone(self):
        ec2 = aws_stack.connect_to_service('ec2')
        route53 = aws_stack.connect_to_service('route53')

        name = 'zone123'
        response = route53.create_hosted_zone(Name=name, CallerReference='ref123')
        zone_id = response['HostedZone']['Id']
        zone_id = zone_id.replace('/hostedzone/', '')

        # associate zone with VPC
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/24')
        vpc_id = vpc['Vpc']['VpcId']
        vpc_region = aws_stack.get_region()
        result = route53.associate_vpc_with_hosted_zone(HostedZoneId=zone_id,
            VPC={'VPCRegion': vpc_region, 'VPCId': vpc_id}, Comment='test 123')
        self.assertTrue(result['ChangeInfo'].get('Id'))

        # list zones by VPC
        result = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=vpc_region)['HostedZoneSummaries']
        expected = {'HostedZoneId': zone_id, 'Name': '%s.' % name,
            'Owner': {'OwningAccount': constants.TEST_AWS_ACCOUNT_ID}}
        self.assertIn(expected, result)

        # list zones by name
        result = route53.list_hosted_zones_by_name(DNSName=name).get('HostedZones')
        self.assertEqual(result[0]['Name'], 'zone123.')
        result = route53.list_hosted_zones_by_name(DNSName='%s.' % name).get('HostedZones')
        self.assertEqual(result[0]['Name'], 'zone123.')

        result = route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={'VPCRegion': aws_stack.get_region(), 'VPCId': vpc_id}, Comment='test2')
        self.assertIn(response['ResponseMetadata']['HTTPStatusCode'], [200, 201])
        # subsequent call (after disassociation) should fail with 404 error
        with self.assertRaises(Exception):
            route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id, VPC={'VPCRegion': aws_stack.get_region(), 'VPCId': vpc_id})

    def test_reusable_delegation_sets(self):
        client = aws_stack.connect_to_service('route53')

        sets_before = client.list_reusable_delegation_sets()['DelegationSets']

        call_ref = 'c-%s' % short_uid()
        result = client.create_reusable_delegation_set(CallerReference=call_ref)['DelegationSet']
        set_id = result['Id']

        result = client.get_reusable_delegation_set(Id=set_id)
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(result['DelegationSet']['Id'], set_id)

        result = client.list_reusable_delegation_sets()
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(len(result['DelegationSets']), len(sets_before) + 1)

        result = client.delete_reusable_delegation_set(Id=set_id)
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)

        with self.assertRaises(Exception) as ctx:
            client.get_reusable_delegation_set(Id=set_id)
        self.assertIn('404', str(ctx.exception))
