import contextlib
import logging

import pytest
from botocore.exceptions import ClientError
from moto.ec2 import ec2_backends
from moto.ec2.utils import (
    random_security_group_id,
    random_subnet_id,
    random_vpc_id,
)

from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.services.ec2.patches import VpcIdentifier
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# public amazon image used for ec2 launch templates
PUBLIC_AMAZON_LINUX_IMAGE = "ami-06c39ed6b42908a36"
PUBLIC_AMAZON_UBUNTU_IMAGE = "ami-03e08697c325f02ab"


@pytest.fixture()
def create_launch_template(aws_client):
    template_ids = []

    def create(template_name):
        response = aws_client.ec2.create_launch_template(
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
            aws_client.ec2.delete_launch_template(LaunchTemplateId=id)


@pytest.fixture()
def create_vpc(aws_client):
    vpcs = []

    def _create_vpc(
        cidr_block: str,
        tag_specifications: list[dict] | None = None,
    ):
        tag_specifications = tag_specifications or []
        vpc = aws_client.ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=tag_specifications)
        vpcs.append(vpc["Vpc"]["VpcId"])
        return vpc

    yield _create_vpc

    for vpc_id in vpcs:
        # Best effort deletion of VPC resources
        try:
            aws_client.ec2.delete_vpc(VpcId=vpc_id)
        except Exception:
            pass


class TestEc2Integrations:
    @markers.snapshot.skip_snapshot_verify(paths=["$..PropagatingVgws"])
    @markers.aws.validated
    def test_create_route_table_association(self, cleanups, aws_client, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("vpc_id"),
                snapshot.transform.key_value("subnet_id"),
                snapshot.transform.key_value("route_table_id"),
                snapshot.transform.key_value("association_id"),
                snapshot.transform.key_value("ClientToken"),
            ]
        )
        vpc_id = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc_id))
        snapshot.match("vpc_id", vpc_id)

        subnet_id = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")["Subnet"][
            "SubnetId"
        ]
        cleanups.append(lambda: aws_client.ec2.delete_subnet(SubnetId=subnet_id))
        snapshot.match("subnet_id", subnet_id)

        route_table_id = aws_client.ec2.create_route_table(VpcId=vpc_id)["RouteTable"][
            "RouteTableId"
        ]
        cleanups.append(lambda: aws_client.ec2.delete_route_table(RouteTableId=route_table_id))
        snapshot.match("route_table_id", route_table_id)

        association_id = aws_client.ec2.associate_route_table(
            RouteTableId=route_table_id,
            SubnetId=subnet_id,
        )["AssociationId"]
        cleanups.append(
            lambda: aws_client.ec2.disassociate_route_table(AssociationId=association_id)
        )
        snapshot.match("association_id", association_id)

        route_tables = aws_client.ec2.describe_route_tables(RouteTableIds=[route_table_id])[
            "RouteTables"
        ]
        snapshot.match("route_tables", route_tables)

        aws_client.ec2.disassociate_route_table(AssociationId=association_id)
        for route_tables in aws_client.ec2.describe_route_tables(RouteTableIds=[route_table_id])[
            "RouteTables"
        ]:
            assert route_tables["Associations"] == []

    @markers.aws.needs_fixing
    # TODO LocalStack fails to delete endpoints
    #  LocalStack does not properly initiate Endpoints with no VpcEndpointType fix probably needed in moto
    #  AWS does not allow for lowercase VpcEndpointType: gateway => Gateway
    def test_create_vpc_endpoint(self, cleanups, aws_client):
        vpc = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc["Vpc"]["VpcId"]))
        subnet = aws_client.ec2.create_subnet(VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.0.0/24")
        cleanups.append(lambda: aws_client.ec2.delete_subnet(SubnetId=subnet["Subnet"]["SubnetId"]))
        route_table = aws_client.ec2.create_route_table(VpcId=vpc["Vpc"]["VpcId"])
        cleanups.append(
            lambda: aws_client.ec2.delete_route_table(
                RouteTableId=route_table["RouteTable"]["RouteTableId"]
            )
        )

        # test without any endpoint type specified
        vpc_endpoint = aws_client.ec2.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTable"]["RouteTableId"]],
        )
        cleanups.append(
            lambda: aws_client.ec2.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]]
            )
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_endpoint["VpcEndpoint"]["ServiceName"]
        assert (
            route_table["RouteTable"]["RouteTableId"]
            == vpc_endpoint["VpcEndpoint"]["RouteTableIds"][0]
        )
        assert vpc["Vpc"]["VpcId"] == vpc_endpoint["VpcEndpoint"]["VpcId"]
        assert 0 == len(vpc_endpoint["VpcEndpoint"]["DnsEntries"])

        # test with any endpoint type as gateway
        vpc_endpoint = aws_client.ec2.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTable"]["RouteTableId"]],
            VpcEndpointType="gateway",
        )
        cleanups.append(
            lambda: aws_client.ec2.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]]
            )
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_endpoint["VpcEndpoint"]["ServiceName"]
        assert (
            route_table["RouteTable"]["RouteTableId"]
            == vpc_endpoint["VpcEndpoint"]["RouteTableIds"][0]
        )
        assert vpc["Vpc"]["VpcId"] == vpc_endpoint["VpcEndpoint"]["VpcId"]
        assert 0 == len(vpc_endpoint["VpcEndpoint"]["DnsEntries"])

        # test with endpoint type as interface
        vpc_endpoint = aws_client.ec2.create_vpc_endpoint(
            VpcId=vpc["Vpc"]["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            SubnetIds=[subnet["Subnet"]["SubnetId"]],
            VpcEndpointType="interface",
        )
        cleanups.append(
            lambda: aws_client.ec2.delete_vpc_endpoints(
                VpcEndpointIds=[vpc_endpoint["VpcEndpoint"]["VpcEndpointId"]]
            )
        )

        assert "com.amazonaws.us-east-1.s3" == vpc_endpoint["VpcEndpoint"]["ServiceName"]
        assert subnet["Subnet"]["SubnetId"] == vpc_endpoint["VpcEndpoint"]["SubnetIds"][0]
        assert vpc["Vpc"]["VpcId"] == vpc_endpoint["VpcEndpoint"]["VpcId"]
        assert len(vpc_endpoint["VpcEndpoint"]["DnsEntries"]) > 0

    @markers.aws.only_localstack
    # This test would attempt to purchase Reserved instance.
    def test_reserved_instance_api(self, aws_client):
        rs = aws_client.ec2.describe_reserved_instances_offerings(
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

        rs = aws_client.ec2.purchase_reserved_instances_offering(
            InstanceCount=1,
            ReservedInstancesOfferingId="string",
            LimitPrice={"Amount": 100.0, "CurrencyCode": "USD"},
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        rs = aws_client.ec2.describe_reserved_instances(
            OfferingClass="standard",
            ReservedInstancesIds=[
                "string",
            ],
            OfferingType="Heavy Utilization",
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # AWS doesn't populate all info of the requester to the peer describe until connection available
            "$..pending-acceptance..VpcPeeringConnections..AccepterVpcInfo.CidrBlock",
            "$..pending-acceptance..VpcPeeringConnections..AccepterVpcInfo.PeeringOptions",
            # LS leaves as `[]`
            "$..VpcPeeringConnections..AccepterVpcInfo.CidrBlockSet",
            "$..VpcPeeringConnections..RequesterVpcInfo.CidrBlockSet",
            # LS adds, not on AWS
            "$..VpcPeeringConnections..AccepterVpcInfo.Ipv6CidrBlockSet",
            "$..VpcPeeringConnections..RequesterVpcInfo.Ipv6CidrBlockSet",
            # LS doesn't add
            "$..VpcPeeringConnections..ExpirationTime",
        ]
    )
    @markers.aws.validated
    def test_vcp_peering_difference_regions(
        self, aws_client_factory, region_name, cleanups, snapshot, secondary_region_name
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("vpc-id"),
                snapshot.transform.key_value("peering-connection-id"),
                snapshot.transform.key_value("region"),
            ]
        )
        region1 = region_name
        region2 = secondary_region_name
        ec2_client1 = aws_client_factory(region_name=region1).ec2
        ec2_client2 = aws_client_factory(region_name=region2).ec2

        def _delete_vpc(client, vpc_id):
            # The Peering connection in the peer vpc might have a delay to detach from the vpc
            return lambda: retry(lambda: client.delete_vpc(VpcId=vpc_id), retries=10, sleep=5)

        # CIDR range can't overlap when creating peering connection
        cidr_block1 = "192.168.1.0/24"
        cidr_block2 = "192.168.2.0/24"
        peer_vpc1_id = ec2_client1.create_vpc(CidrBlock=cidr_block1)["Vpc"]["VpcId"]
        cleanups.append(_delete_vpc(ec2_client1, peer_vpc1_id))
        snapshot.match("vpc1", {"vpc-id": peer_vpc1_id, "region": region1})

        peer_vpc2_id = ec2_client2.create_vpc(CidrBlock=cidr_block2)["Vpc"]["VpcId"]
        cleanups.append(_delete_vpc(ec2_client2, peer_vpc2_id))
        snapshot.match("vpc2", {"vpc-id": peer_vpc2_id, "region": region2})

        peering_connection_id = ec2_client1.create_vpc_peering_connection(
            VpcId=peer_vpc1_id,
            PeerVpcId=peer_vpc2_id,
            PeerRegion=region2,
        )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
        cleanups.append(
            lambda: ec2_client1.delete_vpc_peering_connection(
                VpcPeeringConnectionId=peering_connection_id
            )
        )
        snapshot.match("peering-connection-id", peering_connection_id)

        def _describe_peering_connections(client, expected_status):
            response = client.describe_vpc_peering_connections(
                VpcPeeringConnectionIds=[peering_connection_id]
            )
            assert response["VpcPeeringConnections"][0]["Status"]["Code"] == expected_status
            return response

        # wait for the peering connection to be observable in the peer region
        pending_peer = retry(
            lambda: _describe_peering_connections(ec2_client2, "pending-acceptance"),
            retries=10,
            sleep=5,
        )
        snapshot.match("pending-acceptance", pending_peer)

        # Not creating a snapshot of the response as aws isn't consistent
        ec2_client2.accept_vpc_peering_connection(VpcPeeringConnectionId=peering_connection_id)

        # wait for peering connection to be active in the requester region
        requester_peer = retry(
            lambda: _describe_peering_connections(ec2_client1, "active"), retries=10, sleep=5
        )
        snapshot.match("requester-peer", requester_peer)

        # wait for peering connection to be active in the peer region
        accepter_peer = retry(
            lambda: _describe_peering_connections(ec2_client2, "active"), retries=10, sleep=5
        )
        snapshot.match("accepter-peer", accepter_peer)

    @markers.snapshot.skip_snapshot_verify(
        paths=["$..AmazonSideAsn", "$..AvailabilityZone", "$..Tags"]
    )
    @markers.aws.validated
    def test_describe_vpn_gateways_filter_by_vpc(self, aws_client, cleanups, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("vpc-id"),
                snapshot.transform.key_value("VpnGatewayId"),
            ]
        )

        vpc_id = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc_id))
        snapshot.match("vpc-id", vpc_id)

        gateway = aws_client.ec2.create_vpn_gateway(AvailabilityZone="us-east-1a", Type="ipsec.1")
        gateway_id = gateway["VpnGateway"]["VpnGatewayId"]
        cleanups.append(lambda: aws_client.ec2.delete_vpn_gateway(VpnGatewayId=gateway_id))
        snapshot.match("gateway", gateway)

        def _detach_vpn_gateway():
            aws_client.ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=gateway_id)
            # This is a bit convoluted, but trying to delete a vpc with an attached vpn gateway
            # fails silently. So a simple retry on the delete_vpc will not work.
            retry(
                lambda: aws_client.ec2.describe_vpn_gateways(
                    Filters=[
                        {"Name": "vpn-gateway-id", "Values": [gateway_id]},
                        {"Name": "attachment.state", "Values": ["detached"]},
                    ]
                )["VpnGateways"][0],
                retries=20,
                sleep=5,
            )

        aws_client.ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=gateway_id)
        cleanups.append(_detach_vpn_gateway)

        def _describe_vpn_gateway():
            gateways = aws_client.ec2.describe_vpn_gateways(
                Filters=[
                    {"Name": "attachment.vpc-id", "Values": [vpc_id]},
                ],
            )["VpnGateways"]
            assert gateways[0]["VpcAttachments"][0]["State"] == "attached"
            return gateways[0]

        gateway = retry(_describe_vpn_gateway, retries=20, sleep=5)
        snapshot.match("attached-gateway", gateway)

    @markers.aws.needs_fixing
    # AWS returns 272 elements and a fair bit more information about them than LS
    def test_describe_vpc_endpoints_with_filter(self, aws_client, region_name):
        vpc = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        # test filter of Gateway endpoint services
        vpc_endpoint_gateway_services = aws_client.ec2.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["Gateway"]},
            ],
        )

        assert 200 == vpc_endpoint_gateway_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_gateway_services["ServiceNames"]
        assert 2 == len(services)
        assert f"com.amazonaws.{region_name}.dynamodb" in services
        assert f"com.amazonaws.{region_name}.s3" in services

        # test filter of Interface endpoint services
        vpc_endpoint_interface_services = aws_client.ec2.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["Interface"]},
            ],
        )

        assert 200 == vpc_endpoint_interface_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_interface_services["ServiceNames"]
        assert len(services) > 0
        assert (
            f"com.amazonaws.{region_name}.s3" in services
        )  # S3 is both gateway and interface service
        assert f"com.amazonaws.{region_name}.kinesis-firehose" in services

        # test filter that does not exist
        vpc_endpoint_interface_services = aws_client.ec2.describe_vpc_endpoint_services(
            Filters=[
                {"Name": "service-type", "Values": ["fake"]},
            ],
        )

        assert 200 == vpc_endpoint_interface_services["ResponseMetadata"]["HTTPStatusCode"]
        services = vpc_endpoint_interface_services["ServiceNames"]
        assert len(services) == 0

        # clean up
        aws_client.ec2.delete_vpc(VpcId=vpc_id)

    @markers.aws.validated
    @pytest.mark.parametrize("id_type", ["id", "name"])
    def test_modify_launch_template(self, create_launch_template, id_type, aws_client):
        launch_template_result = create_launch_template(f"template-with-versions-{short_uid()}")
        template = launch_template_result["LaunchTemplate"]

        # call the API identifying the template either by `LaunchTemplateId` or `LaunchTemplateName`
        kwargs = (
            {"LaunchTemplateId": template["LaunchTemplateId"]}
            if (id_type == "id")
            else {"LaunchTemplateName": template["LaunchTemplateName"]}
        )

        new_version_result = aws_client.ec2.create_launch_template_version(
            LaunchTemplateData={"ImageId": PUBLIC_AMAZON_UBUNTU_IMAGE}, **kwargs
        )

        new_default_version = new_version_result["LaunchTemplateVersion"]["VersionNumber"]
        aws_client.ec2.modify_launch_template(
            LaunchTemplateId=template["LaunchTemplateId"],
            DefaultVersion=str(new_default_version),
        )

        modified_template = aws_client.ec2.describe_launch_templates(
            LaunchTemplateIds=[template["LaunchTemplateId"]]
        )
        assert modified_template["LaunchTemplates"][0]["DefaultVersionNumber"] == int(
            new_default_version
        )

    @markers.aws.only_localstack
    def test_create_vpc_with_custom_id(self, aws_client, create_vpc):
        custom_id = random_vpc_id()

        # Check if the custom ID is present
        vpc: dict = create_vpc(
            cidr_block="10.0.0.0/16",
            tag_specifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                    ],
                }
            ],
        )
        assert vpc["Vpc"]["VpcId"] == custom_id

        # Check if the custom ID is present in the describe_vpcs response as well
        vpc: dict = aws_client.ec2.describe_vpcs(VpcIds=[custom_id])["Vpcs"][0]
        assert vpc["VpcId"] == custom_id

        # Check if an duplicate custom ID exception is thrown if we try to recreate the VPC with the same custom ID
        with pytest.raises(ClientError) as e:
            create_vpc(
                cidr_block="10.0.0.0/16",
                tag_specifications=[
                    {
                        "ResourceType": "vpc",
                        "Tags": [
                            {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                        ],
                    }
                ],
            )

        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert e.value.response["Error"]["Code"] == "InvalidVpc.DuplicateCustomId"

    @markers.aws.only_localstack
    def test_create_subnet_with_custom_id(self, aws_client, create_vpc):
        custom_id = random_subnet_id()

        # Create necessary VPC resource
        vpc: dict = create_vpc(cidr_block="10.0.0.0/16", tag_specifications=[])
        vpc_id = vpc["Vpc"]["VpcId"]

        # Check if subnet ID matches the custom ID
        subnet: dict = aws_client.ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.0.0/24",
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                    ],
                }
            ],
        )
        assert subnet["Subnet"]["SubnetId"] == custom_id

        # Check if the custom ID is present in the describe_subnets response as well
        subnet: dict = aws_client.ec2.describe_subnets(
            SubnetIds=[custom_id],
        )["Subnets"][0]
        assert subnet["SubnetId"] == custom_id

        # Check if a duplicate custom ID exception is thrown if we try to recreate the subnet with the same custom ID
        with pytest.raises(ClientError) as e:
            aws_client.ec2.create_subnet(
                CidrBlock="10.0.1.0/24",
                VpcId=vpc_id,
                TagSpecifications=[
                    {
                        "ResourceType": "subnet",
                        "Tags": [
                            {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                        ],
                    }
                ],
            )

        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert e.value.response["Error"]["Code"] == "InvalidSubnet.DuplicateCustomId"

    @markers.aws.only_localstack
    def test_create_subnet_with_custom_id_and_vpc_id(self, aws_client, create_vpc):
        custom_subnet_id = random_subnet_id()
        custom_vpc_id = random_vpc_id()

        # Create the VPC with the custom ID.
        vpc: dict = create_vpc(
            cidr_block="10.0.0.0/16",
            tag_specifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_vpc_id},
                    ],
                }
            ],
        )
        assert vpc["Vpc"]["VpcId"] == custom_vpc_id

        # Check if subnet ID matches the custom ID
        subnet: dict = aws_client.ec2.create_subnet(
            VpcId=custom_vpc_id,
            CidrBlock="10.0.0.0/24",
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_subnet_id},
                    ],
                }
            ],
        )
        assert subnet["Subnet"]["SubnetId"] == custom_subnet_id

        # Check if the custom ID is present in the describe_subnets response as well
        subnet: dict = aws_client.ec2.describe_subnets(
            SubnetIds=[custom_subnet_id],
        )["Subnets"][0]
        assert subnet["SubnetId"] == custom_subnet_id
        assert subnet["VpcId"] == custom_vpc_id

    @markers.aws.only_localstack
    def test_create_security_group_with_custom_id(self, aws_client, create_vpc):
        custom_id = random_security_group_id()

        # Create necessary VPC resource
        vpc: dict = create_vpc(
            cidr_block="10.0.0.0/24",
            tag_specifications=[],
        )

        # Check if security group ID matches the custom ID
        security_group: dict = aws_client.ec2.create_security_group(
            Description="Test security group",
            GroupName="test-security-group-0",
            VpcId=vpc["Vpc"]["VpcId"],
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [
                        {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                    ],
                }
            ],
        )
        assert (
            security_group["GroupId"] == custom_id
        ), f"Security group ID does not match custom ID: {security_group}"

        # Check if the custom ID is present in the describe_security_groups response as well
        security_groups: dict = aws_client.ec2.describe_security_groups(
            GroupIds=[custom_id],
        )["SecurityGroups"]

        # Get security group that match a given VPC id
        security_group = next(
            (sg for sg in security_groups if sg["VpcId"] == vpc["Vpc"]["VpcId"]), None
        )
        assert security_group["GroupId"] == custom_id

        # Check if a duplicate custom ID exception is thrown if we try to recreate the security group with the same custom ID
        with pytest.raises(ClientError) as e:
            aws_client.ec2.create_security_group(
                Description="Test security group",
                GroupName="test-security-group-1",
                VpcId=vpc["Vpc"]["VpcId"],
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": TAG_KEY_CUSTOM_ID, "Value": custom_id},
                        ],
                    }
                ],
            )

        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert e.value.response["Error"]["Code"] == "InvalidSecurityGroupId.DuplicateCustomId"


@markers.snapshot.skip_snapshot_verify(
    # Moto and LS do not return the ClientToken
    paths=["$..ClientToken"],
)
class TestEc2FlowLogs:
    @pytest.fixture
    def create_flow_logs(self, aws_client):
        flow_logs = []

        def _create(**kwargs):
            response = aws_client.ec2.create_flow_logs(**kwargs)
            flow_logs.extend(response.get("FlowLogIds", []))
            return response

        yield _create

        try:
            aws_client.ec2.delete_flow_logs(FlowLogIds=flow_logs)
        except Exception:
            LOG.debug("Error while cleaning up FlowLogs %s", flow_logs)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # not returned by Moto
            "$..FlowLogs..DestinationOptions",
            "$..FlowLogs..Tags",
        ],
    )
    @markers.aws.validated
    def test_ec2_flow_logs_s3(self, aws_client, create_vpc, s3_bucket, create_flow_logs, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("ClientToken"),
                snapshot.transform.key_value("FlowLogId"),
                snapshot.transform.key_value("ResourceId"),
                snapshot.transform.resource_name(),
                snapshot.transform.jsonpath(
                    "$.create-flow-logs-s3-subfolder.FlowLogIds[0]",
                    value_replacement="flow-log-id-sub",
                ),
            ]
        )
        vpc = create_vpc(
            cidr_block="10.0.0.0/24",
            tag_specifications=[],
        )
        vpc_id = vpc["Vpc"]["VpcId"]

        response = create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            LogDestinationType="s3",
            LogDestination=f"arn:aws:s3:::{s3_bucket}",
            TrafficType="ALL",
        )
        snapshot.match("create-flow-logs-s3", response)

        describe_flow_logs = aws_client.ec2.describe_flow_logs(FlowLogIds=response["FlowLogIds"])
        snapshot.match("describe-flow-logs", describe_flow_logs)

        response = create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            LogDestinationType="s3",
            LogDestination=f"arn:aws:s3:::{s3_bucket}/subfolder/",
            TrafficType="ALL",
        )
        snapshot.match("create-flow-logs-s3-subfolder", response)

    @markers.aws.validated
    def test_ec2_flow_logs_s3_validation(
        self, aws_client, create_vpc, create_flow_logs, s3_bucket, snapshot
    ):
        bad_bucket_name = f"{s3_bucket}-{short_uid()}-{short_uid()}"
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("ClientToken"),
                snapshot.transform.key_value("ResourceId"),
                snapshot.transform.regex(bad_bucket_name, replacement="<bad-bucket-name>"),
            ]
        )
        vpc = create_vpc(
            cidr_block="10.0.0.0/24",
            tag_specifications=[],
        )
        vpc_id = vpc["Vpc"]["VpcId"]

        # TODO: write an IAM test if the bucket exists but there are no permissions:
        # the error would be the following if the bucket exists:
        # Access Denied for LogDestination: bad-bucket. Please check LogDestination permission
        non_existent_bucket = create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            LogDestinationType="s3",
            LogDestination=f"arn:aws:s3:::{bad_bucket_name}",
            TrafficType="ALL",
        )
        snapshot.match("non-existent-bucket", non_existent_bucket)

        with pytest.raises(ClientError) as e:
            create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType="VPC",
                LogDestinationType="s3",
                LogDestination=f"arn:aws:s3:::{s3_bucket}",
                LogGroupName="test-group-name",
                TrafficType="ALL",
            )
        snapshot.match("with-log-group-name", e.value.response)

        with pytest.raises(ClientError) as e:
            create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType="VPC",
                LogDestinationType="s3",
                TrafficType="ALL",
            )
        snapshot.match("no-log-destination", e.value.response)

        with pytest.raises(ClientError) as e:
            create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType="VPC",
                LogDestinationType="s3",
                LogGroupName="test",
                TrafficType="ALL",
            )
        snapshot.match("log-group-name-s3-destination", e.value.response)


@markers.aws.validated
def test_raise_modify_to_invalid_default_version(create_launch_template, aws_client):
    launch_template_result = create_launch_template(f"my-first-launch-template-{short_uid()}")
    template = launch_template_result["LaunchTemplate"]

    with pytest.raises(ClientError) as e:
        aws_client.ec2.modify_launch_template(
            LaunchTemplateId=template["LaunchTemplateId"], DefaultVersion="666"
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "InvalidLaunchTemplateId.VersionNotFound"


@markers.aws.validated
def test_raise_when_launch_template_data_missing(aws_client):
    with pytest.raises(ClientError) as e:
        aws_client.ec2.create_launch_template(
            LaunchTemplateName=f"unique_name-{short_uid()}", LaunchTemplateData={}
        )
    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "MissingParameter"


@markers.aws.validated
def test_raise_invalid_launch_template_name(create_launch_template):
    with pytest.raises(ClientError) as e:
        create_launch_template(f"some illegal name {short_uid()}")

    assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert e.value.response["Error"]["Code"] == "InvalidLaunchTemplateName.MalformedException"


@markers.aws.validated
def test_raise_duplicate_launch_template_name(create_launch_template):
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


@markers.aws.only_localstack
def test_pickle_ec2_backend(pickle_backends, aws_client):
    _ = aws_client.ec2.describe_account_attributes()
    pickle_backends(ec2_backends)
    assert pickle_backends(ec2_backends)


@markers.aws.only_localstack
def test_create_specific_vpc_id(account_id, region_name, create_vpc, set_resource_custom_id):
    cidr_block = "10.0.0.0/16"
    custom_id = "my-custom-id"
    set_resource_custom_id(
        VpcIdentifier(account_id=account_id, region=region_name, cidr_block=cidr_block),
        f"vpc-{custom_id}",
    )

    vpc = create_vpc(cidr_block=cidr_block)
    assert vpc["Vpc"]["VpcId"] == f"vpc-{custom_id}"
