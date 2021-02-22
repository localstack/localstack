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

    def test_reserved_instance_api(self):
        rs = self.ec2_client.describe_reserved_instances_offerings(
            AvailabilityZone='us-east-1a',
            IncludeMarketplace=True,
            InstanceType='t2.small',
            OfferingClass='standard',
            ProductDescription='Linux/UNIX',
            ReservedInstancesOfferingIds=[
                'string',
            ],
            OfferingType='Heavy Utilization'
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = self.ec2_client.purchase_reserved_instances_offering(
            InstanceCount=1,
            ReservedInstancesOfferingId='string',
            LimitPrice={
                'Amount': 100.0,
                'CurrencyCode': 'USD'
            }
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = self.ec2_client.describe_reserved_instances(
            OfferingClass='standard',
            ReservedInstancesIds=[
                'string',
            ],
            OfferingType='Heavy Utilization'
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_vcp_peering_difference_regions(self):
        # Note: different regions currently not supported due to set_default_region_in_headers(..) in edge.py
        region1 = 'ap-southeast-1'
        region2 = 'us-east-2'
        region1 = region2 = aws_stack.get_region()
        ec2_client1 = aws_stack.connect_to_service(service_name='ec2', region_name=region1)
        ec2_client2 = aws_stack.connect_to_service(service_name='ec2', region_name=region2)

        cidr_block1 = '192.168.1.2/24'
        cidr_block2 = '192.168.1.2/24'
        peer_vpc1 = ec2_client1.create_vpc(CidrBlock=cidr_block1)
        peer_vpc2 = ec2_client2.create_vpc(CidrBlock=cidr_block2)

        self.assertEqual(peer_vpc1['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(peer_vpc1['Vpc']['CidrBlock'], cidr_block1)
        self.assertEqual(peer_vpc2['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(peer_vpc2['Vpc']['CidrBlock'], cidr_block2)

        cross_region = ec2_client1.create_vpc_peering_connection(
            PeerVpcId=peer_vpc2['Vpc']['VpcId'], VpcId=peer_vpc1['Vpc']['VpcId'], PeerRegion=region2)
        self.assertEqual(peer_vpc1['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(
            peer_vpc1['Vpc']['VpcId'],
            cross_region['VpcPeeringConnection']['RequesterVpcInfo']['VpcId']
        )
        self.assertEqual(
            peer_vpc2['Vpc']['VpcId'],
            cross_region['VpcPeeringConnection']['AccepterVpcInfo']['VpcId']
        )

        accept_vpc = ec2_client2.accept_vpc_peering_connection(
            VpcPeeringConnectionId=cross_region['VpcPeeringConnection']['VpcPeeringConnectionId']
        )
        self.assertEqual(accept_vpc['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(
            peer_vpc1['Vpc']['VpcId'],
            accept_vpc['VpcPeeringConnection']['RequesterVpcInfo']['VpcId']
        )
        self.assertEqual(
            peer_vpc2['Vpc']['VpcId'],
            accept_vpc['VpcPeeringConnection']['AccepterVpcInfo']['VpcId']
        )
        self.assertEqual(
            cross_region['VpcPeeringConnection']['VpcPeeringConnectionId'],
            accept_vpc['VpcPeeringConnection']['VpcPeeringConnectionId']
        )

        requester_peer = ec2_client1.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[accept_vpc['VpcPeeringConnection']['VpcPeeringConnectionId']]
        )
        self.assertEqual(len(requester_peer['VpcPeeringConnections']), 1)
        self.assertEqual(
            region1, requester_peer['VpcPeeringConnections'][0]['RequesterVpcInfo']['Region']
        )
        self.assertEqual(
            region2, requester_peer['VpcPeeringConnections'][0]['AccepterVpcInfo']['Region']
        )

        accepter_peer = ec2_client2.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[accept_vpc['VpcPeeringConnection']['VpcPeeringConnectionId']]
        )
        self.assertEqual(len(accepter_peer['VpcPeeringConnections']), 1)
        self.assertEquals(
            region1, accepter_peer['VpcPeeringConnections'][0]['RequesterVpcInfo']['Region']
        )
        self.assertEquals(
            region2, accepter_peer['VpcPeeringConnections'][0]['AccepterVpcInfo']['Region']
        )

        # Clean up
        ec2_client1.delete_vpc_peering_connection(
            VpcPeeringConnectionId=cross_region['VpcPeeringConnection']['VpcPeeringConnectionId']
        )

        ec2_client1.delete_vpc(VpcId=peer_vpc1['Vpc']['VpcId'])
        ec2_client2.delete_vpc(VpcId=peer_vpc2['Vpc']['VpcId'])

    def test_describe_vpn_gateways_filter_by_vpc(self):
        ec2 = self.ec2_client

        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = vpc['Vpc']['VpcId']

        gateway = ec2.create_vpn_gateway(AvailabilityZone='us-east-1a', Type='ipsec.1')
        self.assertEqual(200, gateway['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual('ipsec.1', gateway['VpnGateway']['Type'])
        self.assertIsNotNone(gateway['VpnGateway']['VpnGatewayId'])

        gateway_id = gateway['VpnGateway']['VpnGatewayId']

        ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=gateway_id)

        gateways = ec2.describe_vpn_gateways(
            Filters=[
                {
                    'Name': 'attachment.vpc-id',
                    'Values': [vpc_id]
                },
            ],
        )
        self.assertEqual(200, gateways['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(1, len(gateways['VpnGateways']))
        self.assertEqual(gateway_id, gateways['VpnGateways'][0]['VpnGatewayId'])
        self.assertEqual('attached', gateways['VpnGateways'][0]['VpcAttachments'][0]['State'])
        self.assertEqual(vpc_id, gateways['VpnGateways'][0]['VpcAttachments'][0]['VpcId'])

        # clean up
        ec2.delete_vpn_gateway(VpnGatewayId=gateway_id)
        ec2.delete_vpc(VpcId=vpc_id)

    def test_terminate_instances(self):
        ec2 = self.ec2_client
        kwargs = {
            'MinCount': 1,
            'MaxCount': 1,
            'ImageId': 'ami-d3adb33f',
            'KeyName': 'the_key',
            'InstanceType': 't1.micro',
            'BlockDeviceMappings': [{'DeviceName': '/dev/sda2', 'Ebs': {'VolumeSize': 50}}],
        }

        resp1 = ec2.run_instances(**kwargs)

        instances = []
        for instance in resp1['Instances']:
            instances.append(instance.get('InstanceId'))

        resp = ec2.terminate_instances(InstanceIds=instances)
        self.assertEqual(instances[0], resp['TerminatingInstances'][0]['InstanceId'])
