import unittest
import random
from localstack.utils.aws import aws_stack


class TestElbv2Integrations(unittest.TestCase):
    def setUp(self):
        self.elbv2_client = aws_stack.connect_to_service('elbv2')
        self.ec2_client = aws_stack.connect_to_service('ec2')

    def test_elbv2_describe_load_balancers(self):
        elbv2 = self.elbv2_client
        ec2 = self.ec2_client

        vpc = ec2.create_vpc(CidrBlock='172.28.7.0/24', InstanceTenancy='default')
        subnet0 = ec2.create_subnet(
            VpcId=vpc['Vpc']['VpcId'], CidrBlock='172.28.7.192/26', AvailabilityZone='us-east-1a'
        )
        subnet1 = ec2.create_subnet(
            VpcId=vpc['Vpc']['VpcId'], CidrBlock='172.28.7.0/26', AvailabilityZone='us-east-1b'
        )

        response = elbv2.create_load_balancer(
            Name=''.join(random.choice('0123abcd') for i in range(3)),
            Subnets=[subnet0['Subnet']['SubnetId'], subnet1['Subnet']['SubnetId']],
            Scheme='internal',
            Tags=[{'Key': 'key_name', 'Value': 'a_value'}],
        )

        lb = response.get('LoadBalancers')[0]
        self.assertEqual(lb['AvailabilityZones'][0]['SubnetId'], subnet0['Subnet']['SubnetId'])
        self.assertEqual(lb['AvailabilityZones'][1]['SubnetId'], subnet1['Subnet']['SubnetId'])
