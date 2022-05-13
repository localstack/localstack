import os


def test_vpc_creates_default_sg(deploy_cfn_template, ec2_client):
    """tests GetAtt references to default security groups and network ACLs for VPCs"""

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
