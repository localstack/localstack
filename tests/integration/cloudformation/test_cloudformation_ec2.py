import os

import pytest


def test_vpc_creates_default_sg(deploy_cfn_template, ec2_client):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/ec2_vpc_default_sg.yaml"
        )
    )

    vpc_id = result.outputs.get("VpcId")
    default_sg = result.outputs.get("VpcDefaultSG")
    default_acl = result.outputs.get("VpcDefaultAcl")

    assert vpc_id
    assert default_sg
    assert default_acl

    security_groups = ec2_client.describe_security_groups(GroupIds=[default_sg])["SecurityGroups"]
    assert security_groups[0]["VpcId"] == vpc_id

    acls = ec2_client.describe_network_acls(NetworkAclIds=[default_acl])["NetworkAcls"]
    assert acls[0]["VpcId"] == vpc_id


@pytest.mark.aws_validated
def test_cfn_with_multiple_route_tables(ec2_client, deploy_cfn_template):

    result = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/template36.yaml"),
        max_wait=180,
    )
    vpc_id = result.outputs["VPC"]

    resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    # 4 route tables being created (validated against AWS): 3 in template + 1 default = 4
    assert len(resp["RouteTables"]) == 4


def test_cfn_with_multiple_route_table_associations(ec2_client, deploy_cfn_template):
    # TODO: stack does not deploy to AWS
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/template37.yaml")
    )
    route_table_id = stack.outputs["RouteTable"]
    route_table = ec2_client.describe_route_tables(
        Filters=[{"Name": "route-table-id", "Values": [route_table_id]}]
    )["RouteTables"][0]

    assert len(route_table["Associations"]) == 2

    # assert subnet attributes are present
    vpc_id = stack.outputs["VpcId"]
    response = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnets = response["Subnets"]
    subnet1 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.0.0/24"][0]
    subnet2 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.2.0/24"][0]
    assert subnet1["AssignIpv6AddressOnCreation"] is True
    assert subnet1["EnableDns64"] is True
    assert subnet1["MapPublicIpOnLaunch"] is True
    assert subnet2["PrivateDnsNameOptionsOnLaunch"]["HostnameType"] == "ip-name"
