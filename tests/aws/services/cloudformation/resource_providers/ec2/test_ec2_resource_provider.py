import os

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..KeyPairs..KeyType",
        "$..KeyPairs..Tags",
        "$..Error..Message",
    ]
)
def test_deploy_instance_with_key_pair(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("KeyName"))
    snapshot.add_transformer(snapshot.transform.key_value("KeyPairId"))
    snapshot.add_transformer(snapshot.transform.key_value("KeyFingerprint"))

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_keypair.yml"
        )
    )

    key_name = stack.outputs["KeyPairName"]

    response = aws_client.ec2.describe_key_pairs(KeyNames=[key_name])
    snapshot.match("key_pair", response)

    stack.destroy()

    with pytest.raises(ClientError) as e:
        aws_client.ec2.describe_key_pairs(KeyNames=[key_name])
    snapshot.match("key_pair_deleted", e.value.response)


@markers.aws.validated
def test_deploy_prefix_list(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_prefixlist.yml"
        )
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    description = aws_client.cloudformation.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("resource-description", description)

    prefix_id = stack.outputs["PrefixRef"]
    prefix_list = aws_client.ec2.describe_managed_prefix_lists(PrefixListIds=[prefix_id])
    snapshot.match("prefix-list", prefix_list)
    snapshot.add_transformer(snapshot.transform.key_value("PrefixListId"))


@markers.aws.validated
def test_deploy_security_group_with_tags(deploy_cfn_template, aws_client, snapshot):
    """Create security group in default VPC with tags."""
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_security_group_with_tags.yml"
        )
    )

    snapshot.add_transformer(snapshot.transform.key_value("GroupId"))
    snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcId"))
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_id, "<stack-id>"))
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack-name>"))
    snapshot.add_transformer(SortingTransformer("Tags", lambda tag: tag["Key"]))
    response = aws_client.ec2.describe_security_groups(GroupIds=[stack.outputs["SecurityGroupId"]])
    security_group = response["SecurityGroups"][0]

    snapshot.match("security-group", security_group)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..DnsEntries",
        "$..Groups",
        "$..NetworkInterfaceIds",
        "$..SubnetIds",
    ]
)
def test_deploy_vpc_endpoint(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_vpc_endpoint.yml"
        )
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    snapshot.add_transformer(
        SortingTransformer("StackResources", lambda sr: sr["LogicalResourceId"]), priority=-1
    )
    description = aws_client.cloudformation.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("resource-description", description)

    endpoint_id = stack.outputs["EndpointRef"]
    endpoint = aws_client.ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
    snapshot.match("endpoint", endpoint)

    snapshot.add_transformer(snapshot.transform.key_value("VpcEndpointId"))
    snapshot.add_transformer(snapshot.transform.key_value("DnsName"))
    snapshot.add_transformer(snapshot.transform.key_value("HostedZoneId"))
    snapshot.add_transformer(snapshot.transform.key_value("GroupId"))
    snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["VpcId"], "vpc-id"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["SubnetBId"], "subnet-b-id"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["SubnetAId"], "subnet-a-id"))
