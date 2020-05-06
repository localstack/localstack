import unittest
from localstack.utils.aws import aws_stack


class TestEc2Integrations(unittest.TestCase):
    def setUp(self):
        self.ec2_client = aws_stack.connect_to_service('ec2')

    def test_create_vpc_end_point(self):

        ec2 = self.ec2_client
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.0.0/24')

        route_table = ec2.create_route_table(VpcId=vpc['Vpc']['VpcId'])

        # test without any end point type specified
        vpc_end_point = ec2.create_vpc_endpoint(
            VpcId=vpc['Vpc']['VpcId'],
            ServiceName='com.amazonaws.us-east-1.s3',
            RouteTableIds=[route_table['RouteTable']['RouteTableId']]
        )

        self.assertEquals(vpc_end_point['VpcEndpoint']['ServiceName'], 'com.amazonaws.us-east-1.s3')
        self.assertEquals(vpc_end_point['VpcEndpoint']['RouteTableIds'][0], route_table['RouteTable']['RouteTableId'])
        self.assertEquals(vpc_end_point['VpcEndpoint']['VpcId'], vpc['Vpc']['VpcId'])
        self.assertEquals(len(vpc_end_point['VpcEndpoint']['DnsEntries']), 0)

        # test with any end point type as gateway
        vpc_end_point = ec2.create_vpc_endpoint(
            VpcId=vpc['Vpc']['VpcId'],
            ServiceName='com.amazonaws.us-east-1.s3',
            RouteTableIds=[route_table['RouteTable']['RouteTableId']],
            VpcEndpointType='gateway',
        )

        self.assertEquals(vpc_end_point['VpcEndpoint']['ServiceName'], 'com.amazonaws.us-east-1.s3')
        self.assertEquals(vpc_end_point['VpcEndpoint']['RouteTableIds'][0], route_table['RouteTable']['RouteTableId'])
        self.assertEquals(vpc_end_point['VpcEndpoint']['VpcId'], vpc['Vpc']['VpcId'])
        self.assertEquals(len(vpc_end_point['VpcEndpoint']['DnsEntries']), 0)

        # test with end point type as interface
        vpc_end_point = ec2.create_vpc_endpoint(
            VpcId=vpc['Vpc']['VpcId'],
            ServiceName='com.amazonaws.us-east-1.s3',
            SubnetIds=[subnet['Subnet']['SubnetId']],
            VpcEndpointType='interface',
        )

        self.assertEquals(vpc_end_point['VpcEndpoint']['ServiceName'], 'com.amazonaws.us-east-1.s3')
        self.assertEquals(vpc_end_point['VpcEndpoint']['SubnetIds'][0], subnet['Subnet']['SubnetId'])
        self.assertEquals(vpc_end_point['VpcEndpoint']['VpcId'], vpc['Vpc']['VpcId'])
        self.assertGreater(len(vpc_end_point['VpcEndpoint']['DnsEntries']), 0)
