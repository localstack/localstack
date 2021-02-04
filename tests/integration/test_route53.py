import unittest
from localstack.utils.aws import aws_stack


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

        response = route53.create_hosted_zone(Name='zone123', CallerReference='ref123')
        zone_id = response['HostedZone']['Id']

        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']
        result = route53.associate_vpc_with_hosted_zone(HostedZoneId=zone_id,
            VPC={'VPCRegion': aws_stack.get_region(), 'VPCId': vpc_id}, Comment='test 123')
        self.assertTrue(result['ChangeInfo'].get('Id'))

        result = route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={'VPCRegion': aws_stack.get_region(), 'VPCId': vpc_id}, Comment='test2')
        self.assertIn(response['ResponseMetadata']['HTTPStatusCode'], [200, 201])
        # subsequent call (after disassociation) should fail with 404 error
        with self.assertRaises(Exception):
            route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id, VPC={'VPCRegion': aws_stack.get_region(), 'VPCId': vpc_id})
