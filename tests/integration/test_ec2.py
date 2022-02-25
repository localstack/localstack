from localstack.utils.aws import aws_stack


class TestEc2Integrations:
    def test_create_route_table_association(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.0.0/24")

        route_table = ec2_client.create_route_table(VpcId=vpc["Vpc"]["VpcId"])
        association_id = ec2_client.associate_route_table(
            RouteTableId=route_table["RouteTable"]["RouteTableId"],
            SubnetId=subnet["Subnet"]["SubnetId"],
        )["AssociationId"]

        for route_tables in ec2_client.describe_route_tables()["RouteTables"]:
            for association in route_tables["Associations"]:
                if association["RouteTableId"] == route_table["RouteTable"]["RouteTableId"]:
                    if association.get("Main"):
                        continue  # default route table associations have no SubnetId in moto
                    assert association["SubnetId"] == subnet["Subnet"]["SubnetId"]
                    assert association["AssociationState"]["State"] == "associated"

        ec2_client.disassociate_route_table(AssociationId=association_id)
        for route_tables in ec2_client.describe_route_tables()["RouteTables"]:
            associations = [a for a in route_tables["Associations"] if not a.get("Main")]
            assert associations == []

    def test_create_vpc_end_point(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.0.0/24")

        route_table = ec2_client.create_route_table(VpcId=vpc["Vpc"]["VpcId"])

        # test without any end point type specified
        vpc_end_point = ec2_client.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTable"]["RouteTableId"]],
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_end_point["VpcEndpoint"]["ServiceName"]
        assert (
            route_table["RouteTable"]["RouteTableId"]
            == vpc_end_point["VpcEndpoint"]["RouteTableIds"][0]
        )
        assert vpc["Vpc"]["VpcId"] == vpc_end_point["VpcEndpoint"]["VpcId"]
        assert 0 == len(vpc_end_point["VpcEndpoint"]["DnsEntries"])

        # test with any end point type as gateway
        vpc_end_point = ec2_client.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTable"]["RouteTableId"]],
            VpcEndpointType="gateway",
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_end_point["VpcEndpoint"]["ServiceName"]
        assert (
            route_table["RouteTable"]["RouteTableId"]
            == vpc_end_point["VpcEndpoint"]["RouteTableIds"][0]
        )
        assert vpc["Vpc"]["VpcId"] == vpc_end_point["VpcEndpoint"]["VpcId"]
        assert 0 == len(vpc_end_point["VpcEndpoint"]["DnsEntries"])

        # test with end point type as interface
        vpc_end_point = ec2_client.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            SubnetIds=[subnet["Subnet"]["SubnetId"]],
            VpcEndpointType="interface",
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_end_point["VpcEndpoint"]["ServiceName"]
        assert subnet["Subnet"]["SubnetId"] == vpc_end_point["VpcEndpoint"]["SubnetIds"][0]
        assert vpc["Vpc"]["VpcId"] == vpc_end_point["VpcEndpoint"]["VpcId"]
        assert len(vpc_end_point["VpcEndpoint"]["DnsEntries"]) > 0

    def test_reserved_instance_api(self, ec2_client):
        rs = ec2_client.describe_reserved_instances_offerings(
            AvailabilityZone="us-east-1a",
            IncludeMarketplace=True,
            InstanceType="t2.small",
            OfferingClass="standard",
            ProductDescription="Linux/UNIX",
            ReservedInstancesOfferingIds=[
                "string",
            ],
            OfferingType="Heavy Utilization",
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        rs = ec2_client.purchase_reserved_instances_offering(
            InstanceCount=1,
            ReservedInstancesOfferingId="string",
            LimitPrice={"Amount": 100.0, "CurrencyCode": "USD"},
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        rs = ec2_client.describe_reserved_instances(
            OfferingClass="standard",
            ReservedInstancesIds=[
                "string",
            ],
            OfferingType="Heavy Utilization",
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

    def test_vcp_peering_difference_regions(self, ec2_client):
        # Note: different regions currently not supported due to set_default_region_in_headers(..) in edge.py
        region1 = region2 = aws_stack.get_region()
        ec2_client1 = aws_stack.create_external_boto_client(service_name="ec2", region_name=region1)
        ec2_client2 = aws_stack.create_external_boto_client(service_name="ec2", region_name=region2)

        cidr_block1 = "192.168.1.2/24"
        cidr_block2 = "192.168.1.2/24"
        peer_vpc1 = ec2_client1.create_vpc(CidrBlock=cidr_block1)
        peer_vpc2 = ec2_client2.create_vpc(CidrBlock=cidr_block2)

        assert 200 == peer_vpc1["ResponseMetadata"]["HTTPStatusCode"]
        assert cidr_block1 == peer_vpc1["Vpc"]["CidrBlock"]
        assert 200 == peer_vpc2["ResponseMetadata"]["HTTPStatusCode"]
        assert cidr_block2 == peer_vpc2["Vpc"]["CidrBlock"]

        cross_region = ec2_client1.create_vpc_peering_connection(
            PeerVpcId=peer_vpc2["Vpc"]["VpcId"],
            VpcId=peer_vpc1["Vpc"]["VpcId"],
            PeerRegion=region2,
        )
        assert 200 == cross_region["ResponseMetadata"]["HTTPStatusCode"]
        assert (
            peer_vpc1["Vpc"]["VpcId"]
            == cross_region["VpcPeeringConnection"]["RequesterVpcInfo"]["VpcId"]
        )
        assert (
            peer_vpc2["Vpc"]["VpcId"]
            == cross_region["VpcPeeringConnection"]["AccepterVpcInfo"]["VpcId"]
        )

        accept_vpc = ec2_client2.accept_vpc_peering_connection(
            VpcPeeringConnectionId=cross_region["VpcPeeringConnection"]["VpcPeeringConnectionId"]
        )
        assert 200 == accept_vpc["ResponseMetadata"]["HTTPStatusCode"]
        assert (
            peer_vpc1["Vpc"]["VpcId"]
            == accept_vpc["VpcPeeringConnection"]["RequesterVpcInfo"]["VpcId"]
        )
        assert (
            peer_vpc2["Vpc"]["VpcId"]
            == accept_vpc["VpcPeeringConnection"]["AccepterVpcInfo"]["VpcId"]
        )
        assert (
            cross_region["VpcPeeringConnection"]["VpcPeeringConnectionId"]
            == accept_vpc["VpcPeeringConnection"]["VpcPeeringConnectionId"]
        )

        requester_peer = ec2_client1.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[accept_vpc["VpcPeeringConnection"]["VpcPeeringConnectionId"]]
        )
        assert 1 == len(requester_peer["VpcPeeringConnections"])
        assert region1 == requester_peer["VpcPeeringConnections"][0]["RequesterVpcInfo"]["Region"]
        assert region2 == requester_peer["VpcPeeringConnections"][0]["AccepterVpcInfo"]["Region"]

        accepter_peer = ec2_client2.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[accept_vpc["VpcPeeringConnection"]["VpcPeeringConnectionId"]]
        )
        assert 1 == len(accepter_peer["VpcPeeringConnections"])
        assert region1 == accepter_peer["VpcPeeringConnections"][0]["RequesterVpcInfo"]["Region"]
        assert region2 == accepter_peer["VpcPeeringConnections"][0]["AccepterVpcInfo"]["Region"]

        # Clean up
        ec2_client1.delete_vpc_peering_connection(
            VpcPeeringConnectionId=cross_region["VpcPeeringConnection"]["VpcPeeringConnectionId"]
        )

        ec2_client1.delete_vpc(VpcId=peer_vpc1["Vpc"]["VpcId"])
        ec2_client2.delete_vpc(VpcId=peer_vpc2["Vpc"]["VpcId"])

    def test_describe_vpn_gateways_filter_by_vpc(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        gateway = ec2_client.create_vpn_gateway(AvailabilityZone="us-east-1a", Type="ipsec.1")
        assert 200 == gateway["ResponseMetadata"]["HTTPStatusCode"]
        assert "ipsec.1" == gateway["VpnGateway"]["Type"]
        assert gateway["VpnGateway"]["VpnGatewayId"] is not None

        gateway_id = gateway["VpnGateway"]["VpnGatewayId"]

        ec2_client.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=gateway_id)

        gateways = ec2_client.describe_vpn_gateways(
            Filters=[
                {"Name": "attachment.vpc-id", "Values": [vpc_id]},
            ],
        )
        assert 200 == gateways["ResponseMetadata"]["HTTPStatusCode"]
        assert 1 == len(gateways["VpnGateways"])
        assert gateway_id == gateways["VpnGateways"][0]["VpnGatewayId"]
        assert "attached" == gateways["VpnGateways"][0]["VpcAttachments"][0]["State"]
        assert vpc_id == gateways["VpnGateways"][0]["VpcAttachments"][0]["VpcId"]

        # clean up
        ec2_client.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=gateway_id)
        ec2_client.delete_vpn_gateway(VpnGatewayId=gateway_id)
        ec2_client.delete_vpc(VpcId=vpc_id)

    def test_describe_vpc_endpoints_with_filter(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        # test filter of Gateway endpoint services
        vpc_endpoint_gateway_services = ec2_client.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["Gateway"]},
            ],
        )

        region = aws_stack.get_region()
        assert 200 == vpc_endpoint_gateway_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_gateway_services["ServiceNames"]
        assert 2 == len(services)
        assert f"com.amazonaws.{region}.dynamodb" in services
        assert f"com.amazonaws.{region}.s3" in services
        # test filter of Interface endpoint services
        vpc_endpoint_interface_services = ec2_client.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["Interface"]},
            ],
        )

        assert 200 == vpc_endpoint_interface_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_interface_services["ServiceNames"]
        assert len(services) > 0
        assert f"com.amazonaws.{region}.dynamodb" in services
        assert f"com.amazonaws.{region}.s3" in services
        assert f"com.amazonaws.{region}.firehose" in services

        # test filter that does not exist
        vpc_endpoint_interface_services = ec2_client.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["fake"]},
            ],
        )

        assert 200 == vpc_endpoint_interface_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_interface_services["ServiceNames"]
        assert len(services) == 0

        # clean up
        ec2_client.delete_vpc(VpcId=vpc_id)

    def test_terminate_instances(self, ec2_client):
        kwargs = {
            "MinCount": 1,
            "MaxCount": 1,
            "ImageId": "ami-d3adb33f",
            "KeyName": "the_key",
            "InstanceType": "t1.micro",
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda2", "Ebs": {"VolumeSize": 50}}],
        }

        resp1 = ec2_client.run_instances(**kwargs)

        instances = []
        for instance in resp1["Instances"]:
            instances.append(instance.get("InstanceId"))

        resp = ec2_client.terminate_instances(InstanceIds=instances)
        assert instances[0] == resp["TerminatingInstances"][0]["InstanceId"]
