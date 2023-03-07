import contextlib

import pytest
from botocore.exceptions import ClientError
from moto.ec2 import ec2_backends

from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid

# public amazon image used for ec2 launch templates
PUBLIC_AMAZON_LINUX_IMAGE = "ami-06c39ed6b42908a36"
PUBLIC_AMAZON_UBUNTU_IMAGE = "ami-03e08697c325f02ab"


@pytest.fixture()
def create_launch_template(ec2_client):
    template_ids = []

    def create(template_name):
        response = ec2_client.create_launch_template(
            LaunchTemplateName=template_name,
            LaunchTemplateData={
                "ImageId": PUBLIC_AMAZON_LINUX_IMAGE,
            },
        )
        template_ids.append(response["LaunchTemplate"]["LaunchTemplateId"])
        return response

    yield create
    for id in template_ids:
        with contextlib.suppress(ClientError):
            ec2_client.delete_launch_template(LaunchTemplateId=id)


class TestEc2Integrations:
    def test_create_route_table_association(self, ec2_client, cleanups):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        cleanups.append(lambda: ec2_client.delete_vpc(VpcId=vpc["Vpc"]["VpcId"]))
        subnet = ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.0.0/24")
        cleanups.append(lambda: ec2_client.delete_subnet(SubnetId=subnet["Subnet"]["SubnetId"]))

        route_table = ec2_client.create_route_table(VpcId=vpc["Vpc"]["VpcId"])
        cleanups.append(
            lambda: ec2_client.delete_route_table(
                RouteTableId=route_table["RouteTable"]["RouteTableId"]
            )
        )
        association_id = ec2_client.associate_route_table(
            RouteTableId=route_table["RouteTable"]["RouteTableId"],
            SubnetId=subnet["Subnet"]["SubnetId"],
        )["AssociationId"]
        cleanups.append(lambda: ec2_client.disassociate_route_table(AssociationId=association_id))

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

    def test_create_vpc_end_point(self, ec2_client, cleanups):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        cleanups.append(lambda: ec2_client.delete_vpc(VpcId=vpc["Vpc"]["VpcId"]))
        subnet = ec2_client.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.0.0/24")
        cleanups.append(lambda: ec2_client.delete_subnet(SubnetId=subnet["Subnet"]["SubnetId"]))
        route_table = ec2_client.create_route_table(VpcId=vpc["Vpc"]["VpcId"])
        cleanups.append(
            lambda: ec2_client.delete_route_table(
                RouteTableId=route_table["RouteTable"]["RouteTableId"]
            )
        )

        # test without any end point type specified
        vpc_end_point = ec2_client.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTable"]["RouteTableId"]],
        )
        cleanups.append(
            lambda: ec2_client.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_end_point["VpcEndpoint"]["VpcEndpointId"]]
            )
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
        cleanups.append(
            lambda: ec2_client.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_end_point["VpcEndpoint"]["VpcEndpointId"]]
            )
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
        cleanups.append(
            lambda: ec2_client.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_end_point["VpcEndpoint"]["VpcEndpointId"]]
            )
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
        assert f"com.amazonaws.{region}.s3" in services  # S3 is both gateway and interface service
        assert f"com.amazonaws.{region}.kinesis-firehose" in services

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

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("id_type", ["id", "name"])
    def test_modify_launch_template(self, ec2_client, create_launch_template, id_type):
        launch_template_result = create_launch_template(f"template-with-versions-{short_uid()}")
        template = launch_template_result["LaunchTemplate"]

        # call the API identifying the template either by `LaunchTemplateId` or `LaunchTemplateName`
        kwargs = (
            {"LaunchTemplateId": template["LaunchTemplateId"]}
            if (id_type == "id")
            else {"LaunchTemplateName": template["LaunchTemplateName"]}
        )

        new_version_result = ec2_client.create_launch_template_version(
            LaunchTemplateData={"ImageId": PUBLIC_AMAZON_UBUNTU_IMAGE}, **kwargs
        )

        new_default_version = new_version_result["LaunchTemplateVersion"]["VersionNumber"]
        ec2_client.modify_launch_template(
            LaunchTemplateId=template["LaunchTemplateId"],
            DefaultVersion=str(new_default_version),
        )

        modified_template = ec2_client.describe_launch_templates(
            LaunchTemplateIds=[template["LaunchTemplateId"]]
        )
        assert modified_template["LaunchTemplates"][0]["DefaultVersionNumber"] == int(
            new_default_version
        )


@pytest.mark.aws_validated
def test_raise_modify_to_invalid_default_version(ec2_client, create_launch_template):
    launch_template_result = create_launch_template(f"my-first-launch-template-{short_uid()}")
    template = launch_template_result["LaunchTemplate"]

    with pytest.raises(ClientError) as e:
        ec2_client.modify_launch_template(
            LaunchTemplateId=template["LaunchTemplateId"], DefaultVersion="666"
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "InvalidLaunchTemplateId.VersionNotFound"


@pytest.mark.aws_validated
def test_raise_when_launch_template_data_missing(ec2_client):
    with pytest.raises(ClientError) as e:
        ec2_client.create_launch_template(
            LaunchTemplateName=f"unique_name-{short_uid()}", LaunchTemplateData={}
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "MissingParameter"


@pytest.mark.aws_validated
def test_raise_invalid_launch_template_name(create_launch_template):
    with pytest.raises(ClientError) as e:
        create_launch_template(f"some illegal name {short_uid()}")

    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "InvalidLaunchTemplateName.MalformedException"


@pytest.mark.aws_validated
def test_raise_duplicate_launch_template_name(ec2_client, create_launch_template):
    create_launch_template("name")

    with pytest.raises(ClientError) as e:
        create_launch_template("name")

    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "InvalidLaunchTemplateName.AlreadyExistsException"


@pytest.fixture
def pickle_backends():
    def _can_pickle(*args) -> bool:
        import dill

        try:
            for i in args:
                dill.dumps(i)
        except TypeError:
            return False
        return True

    return _can_pickle


def test_pickle_ec2_backend(ec2_client, pickle_backends):
    _ = ec2_client.describe_account_attributes()
    pickle_backends(ec2_backends)
    assert pickle_backends(ec2_backends)
