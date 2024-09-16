import os

import pytest
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

THIS_FOLDER = os.path.dirname(__file__)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..PropagatingVgws"])
def test_simple_route_table_creation_without_vpc(deploy_cfn_template, aws_client, snapshot):
    ec2 = aws_client.ec2
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/ec2_route_table_isolated.yaml"),
    )

    route_table_id = stack.outputs["RouteTableId"]
    route_table = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]

    tags = route_table.pop("Tags")
    tags_dict = {tag["Key"]: tag["Value"] for tag in tags if "aws:cloudformation" not in tag["Key"]}
    snapshot.match("tags", tags_dict)

    snapshot.match("route_table", route_table)
    snapshot.add_transformer(snapshot.transform.key_value("VpcId", "vpc-id"))
    snapshot.add_transformer(snapshot.transform.key_value("RouteTableId", "vpc-id"))

    stack.destroy()
    with pytest.raises(ec2.exceptions.ClientError):
        ec2.describe_route_tables(RouteTableIds=[route_table_id])


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..PropagatingVgws"])
def test_simple_route_table_creation(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/ec2_route_table_simple.yaml")
    )

    route_table_id = stack.outputs["RouteTableId"]
    ec2 = aws_client.ec2
    route_table = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]

    tags = route_table.pop("Tags")
    tags_dict = {tag["Key"]: tag["Value"] for tag in tags if "aws:cloudformation" not in tag["Key"]}
    snapshot.match("tags", tags_dict)

    snapshot.match("route_table", route_table)
    snapshot.add_transformer(snapshot.transform.key_value("VpcId", "vpc-id"))
    snapshot.add_transformer(snapshot.transform.key_value("RouteTableId", "vpc-id"))

    stack.destroy()
    with pytest.raises(ec2.exceptions.ClientError):
        ec2.describe_route_tables(RouteTableIds=[route_table_id])


@markers.aws.validated
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


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..PropagatingVgws", "$..Tags", "$..Tags..Key", "$..Tags..Value"]
)
def test_cfn_with_multiple_route_table_associations(deploy_cfn_template, aws_client, snapshot):
    # TODO: stack does not deploy to AWS
    stack = deploy_cfn_template(
        template_path=os.path.join(THIS_FOLDER, "../../../templates/template37.yaml")
    )
    route_table_id = stack.outputs["RouteTable"]
    route_table = aws_client.ec2.describe_route_tables(
        Filters=[{"Name": "route-table-id", "Values": [route_table_id]}]
    )["RouteTables"][0]

    snapshot.match("route_table", route_table)
    snapshot.add_transformer(snapshot.transform.key_value("RouteTableId"))
    snapshot.add_transformer(snapshot.transform.key_value("RouteTableAssociationId"))
    snapshot.add_transformer(snapshot.transform.key_value("SubnetId"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcId"))


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


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..RouteTables..PropagatingVgws", "$..RouteTables..Tags"]
)
def test_vpc_with_route_table(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/template33.yaml")
    )

    route_id = stack.outputs["RouteTableId"]
    response = aws_client.ec2.describe_route_tables(RouteTableIds=[route_id])

    # Convert tags to dictionary for easier comparison
    response["RouteTables"][0]["Tags"] = {
        tag["Key"]: tag["Value"] for tag in response["RouteTables"][0]["Tags"]
    }

    snapshot.match("route_table", response)

    snapshot.add_transformer(snapshot.transform.regex(stack.stack_id, "<stack_id>"))
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack_name>"))
    snapshot.add_transformer(snapshot.transform.key_value("RouteTableId"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcId"))

    stack.destroy()

    with pytest.raises(aws_client.ec2.exceptions.ClientError):
        aws_client.ec2.describe_route_tables(RouteTableIds=[route_id])


@pytest.mark.skip(reason="update doesn't change value for instancetype")
@markers.aws.validated
def test_cfn_update_ec2_instance_type(deploy_cfn_template, aws_client, cleanups):
    if aws_client.cloudformation.meta.region_name not in [
        "ap-northeast-1",
        "eu-central-1",
        "eu-south-1",
        "eu-west-1",
        "eu-west-2",
        "us-east-1",
    ]:
        pytest.skip()

    key_name = f"testkey-{short_uid()}"
    aws_client.ec2.create_key_pair(KeyName=key_name)
    cleanups.append(lambda: aws_client.ec2.delete_key_pair(KeyName=key_name))

    # get alpine image id
    if is_aws_cloud():
        images = aws_client.ec2.describe_images(
            Filters=[
                {"Name": "name", "Values": ["alpine-3.19.0-x86_64-bios-*"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["Images"]
        image_id = images[0]["ImageId"]
    else:
        image_id = "ami-0a63f96a6a8d4d2c5"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ec2_instance.yml"
        ),
        parameters={"KeyName": key_name, "InstanceType": "t2.nano", "ImageId": image_id},
    )

    instance_id = stack.outputs["InstanceId"]
    instance = aws_client.ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    assert instance["InstanceType"] == "t2.nano"

    deploy_cfn_template(
        stack_name=stack.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ec2_instance.yml"
        ),
        parameters={"KeyName": key_name, "InstanceType": "t2.medium", "ImageId": image_id},
        is_update=True,
    )

    instance = aws_client.ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    assert instance["InstanceType"] == "t2.medium"


@markers.aws.validated
def test_ec2_security_group_id_with_vpc(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ec2_vpc_securitygroup.yml"
        ),
    )

    ec2_client = aws_client.ec2
    with_vpcid_sg_group_id = ec2_client.describe_security_groups(
        Filters=[
            {
                "Name": "group-id",
                "Values": [stack.outputs["SGWithVpcIdGroupId"]],
            },
        ]
    )["SecurityGroups"][0]
    without_vpcid_sg_group_id = ec2_client.describe_security_groups(
        Filters=[
            {
                "Name": "group-id",
                "Values": [stack.outputs["SGWithoutVpcIdGroupId"]],
            },
        ]
    )["SecurityGroups"][0]

    snapshot.add_transformer(
        snapshot.transform.regex(with_vpcid_sg_group_id["GroupId"], "<with-vpcid-group-id>")
    )
    snapshot.add_transformer(
        snapshot.transform.regex(without_vpcid_sg_group_id["GroupId"], "<without-vpcid-group-id>")
    )
    snapshot.add_transformer(
        snapshot.transform.regex(
            without_vpcid_sg_group_id["GroupName"], "<without-vpcid-group-name>"
        )
    )
    snapshot.match("references", stack.outputs)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # fingerprint algorithm is different but presence is ensured by CFn output implementation
        "$..ImportedKeyPairFingerprint",
    ],
)
def test_keypair_create_import(deploy_cfn_template, snapshot, aws_client):
    imported_key_name = f"imported-key-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(imported_key_name, "<imported-key-name>"))
    generated_key_name = f"generated-key-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(generated_key_name, "<generated-key-name>"))
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/ec2_import_keypair.yaml"
        ),
        parameters={"ImportedKeyName": imported_key_name, "GeneratedKeyName": generated_key_name},
    )

    outputs = stack.outputs
    # for the generated key pair, use the EC2 API to get the fingerprint and snapshot the value
    key_res = aws_client.ec2.describe_key_pairs(KeyNames=[outputs["GeneratedKeyPairName"]])[
        "KeyPairs"
    ][0]
    snapshot.add_transformer(snapshot.transform.regex(key_res["KeyFingerprint"], "<fingerprint>"))

    snapshot.match("outputs", outputs)
