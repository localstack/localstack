import os

import pytest
from localstack_snapshot.snapshots import SortingTransformer

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

THIS_FOLDER = os.path.dirname(__file__)


@markers.aws.unknown
def test_simple_route_table_creation_without_vpc(deploy_cfn_template, aws_client):
    ec2 = aws_client.ec2
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/ec2_route_table_isolated.yaml"),
        parameters={"MyVpcId": vpc_id},
    )

    route_table_id = stack.outputs["RouteTableId"]
    route_table = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]
    assert route_table["RouteTableId"] == route_table_id

    stack.destroy()
    with pytest.raises(ec2.exceptions.ClientError):
        ec2.describe_route_tables(RouteTableIds=[route_table_id])
    # TODO move vpc to fixture, so we are sure it is deleted after tests
    ec2.delete_vpc(VpcId=vpc_id)


@markers.aws.unknown
def test_simple_route_table_creation(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/ec2_route_table_simple.yaml")
    )

    route_table_id = stack.outputs["RouteTableId"]
    ec2 = aws_client.ec2
    route_table = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]
    assert route_table["RouteTableId"] == route_table_id

    stack.destroy()
    with pytest.raises(ec2.exceptions.ClientError):
        ec2.describe_route_tables(RouteTableIds=[route_table_id])


@markers.aws.unknown
def test_vpc_creates_default_sg(deploy_cfn_template, aws_client):
    result = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/ec2_vpc_default_sg.yaml")
    )

    vpc_id = result.outputs.get("VpcId")
    default_sg = result.outputs.get("VpcDefaultSG")
    default_acl = result.outputs.get("VpcDefaultAcl")

    assert vpc_id
    assert default_sg
    assert default_acl

    security_groups = aws_client.ec2.describe_security_groups(GroupIds=[default_sg])[
        "SecurityGroups"
    ]
    assert security_groups[0]["VpcId"] == vpc_id

    acls = aws_client.ec2.describe_network_acls(NetworkAclIds=[default_acl])["NetworkAcls"]
    assert acls[0]["VpcId"] == vpc_id


@markers.aws.validated
def test_cfn_with_multiple_route_tables(deploy_cfn_template, aws_client):
    result = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/template36.yaml"),
        max_wait=180,
    )
    vpc_id = result.outputs["VPC"]

    resp = aws_client.ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

    # 4 route tables being created (validated against AWS): 3 in template + 1 default = 4
    assert len(resp["RouteTables"]) == 4


@markers.aws.unknown
def test_cfn_with_multiple_route_table_associations(deploy_cfn_template, aws_client):
    # TODO: stack does not deploy to AWS
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/template37.yaml")
    )
    route_table_id = stack.outputs["RouteTable"]
    route_table = aws_client.ec2.describe_route_tables(
        Filters=[{"Name": "route-table-id", "Values": [route_table_id]}]
    )["RouteTables"][0]

    assert len(route_table["Associations"]) == 2

    # assert subnet attributes are present
    vpc_id = stack.outputs["VpcId"]
    response = aws_client.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnets = response["Subnets"]
    subnet1 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.0.0/24"][0]
    subnet2 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.2.0/24"][0]
    assert subnet1["AssignIpv6AddressOnCreation"] is True
    assert subnet1["EnableDns64"] is True
    assert subnet1["MapPublicIpOnLaunch"] is True
    assert subnet2["PrivateDnsNameOptionsOnLaunch"]["HostnameType"] == "ip-name"


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..DriftInformation", "$..Metadata"])
def test_internet_gateway_ref_and_attr(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/internet_gateway.yml")
    )

    response = aws_client.cloudformation.describe_stack_resource(
        StackName=stack.stack_name, LogicalResourceId="Gateway"
    )

    snapshot.add_transformer(snapshot.transform.key_value("RefAttachment", "internet-gateway-ref"))
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    snapshot.match("outputs", stack.outputs)
    snapshot.match("description", response["StackResourceDetail"])


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Tags", "$..OwnerId"])
def test_dhcp_options(aws_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/dhcp_options.yml")
    )

    response = aws_client.ec2.describe_dhcp_options(
        DhcpOptionsIds=[stack.outputs["RefDhcpOptions"]]
    )
    snapshot.add_transformer(snapshot.transform.key_value("DhcpOptionsId", "dhcp-options-id"))
    snapshot.add_transformer(SortingTransformer("DhcpConfigurations", lambda x: x["Key"]))
    snapshot.match("description", response["DhcpOptions"][0])


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Tags",
        "$..Options.AssociationDefaultRouteTableId",
        "$..Options.PropagationDefaultRouteTableId",
    ]
)
def test_transit_gateway_attachment(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/transit_gateway_attachment.yml")
    )

    gateway_description = aws_client.ec2.describe_transit_gateways(
        TransitGatewayIds=[stack.outputs["TransitGateway"]]
    )
    attachment_description = aws_client.ec2.describe_transit_gateway_attachments(
        TransitGatewayAttachmentIds=[stack.outputs["Attachment"]]
    )

    snapshot.add_transformer(snapshot.transform.key_value("TransitGatewayRouteTableId"))
    snapshot.add_transformer(snapshot.transform.key_value("AssociationDefaultRouteTableId"))
    snapshot.add_transformer(snapshot.transform.key_value("PropagatioDefaultRouteTableId"))
    snapshot.add_transformer(snapshot.transform.key_value("ResourceId"))
    snapshot.add_transformer(snapshot.transform.key_value("TransitGatewayAttachmentId"))
    snapshot.add_transformer(snapshot.transform.key_value("TransitGatewayId"))

    snapshot.match("attachment", attachment_description["TransitGatewayAttachments"][0])
    snapshot.match("gateway", gateway_description["TransitGateways"][0])

    stack.destroy()

    descriptions = aws_client.ec2.describe_transit_gateways(
        TransitGatewayIds=[stack.outputs["TransitGateway"]]
    )
    if is_aws_cloud():
        # aws changes the state to deleted
        descriptions = descriptions["TransitGateways"][0]
        assert descriptions["State"] == "deleted"
    else:
        # moto directly deletes the transit gateway
        transit_gateways_ids = [
            tgateway["TransitGatewayId"] for tgateway in descriptions["TransitGateways"]
        ]
        assert stack.outputs["TransitGateway"] not in transit_gateways_ids

    attachment_description = aws_client.ec2.describe_transit_gateway_attachments(
        TransitGatewayAttachmentIds=[stack.outputs["Attachment"]]
    )["TransitGatewayAttachments"]
    assert attachment_description[0]["State"] == "deleted"
