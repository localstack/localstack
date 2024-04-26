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

    prefix_id = stack.outputs["PrefixRef"]
    prefix_list = aws_client.ec2.describe_managed_prefix_lists(PrefixListIds=[prefix_id])
    snapshot.match("prefix-list", prefix_list)
    snapshot.add_transformer(snapshot.transform.key_value("PrefixListId"))


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..DnsEntries",
        "$..Groups",
        "$..NetworkInterfaceIds",
    ]
)
def test_deploy_vpc_endpoint(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../templates/ec2_vpc_endpoint.yml"
        )
    )

    endpoint_id = stack.outputs["EndpointRef"]
    endpoint = aws_client.ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
    snapshot.match("endpoint", endpoint)

    snapshot.add_transformer(snapshot.transform.key_value("VpcEndpointId"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["VpcId"], "vpc-id"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["SubnetAId"], "subnet-a-id"))
    snapshot.add_transformer(snapshot.transform.regex(stack.outputs["SubnetBId"], "subnet-b-id"))
    snapshot.add_transformer(SortingTransformer("SubnetIds", sorting_fn=lambda x: x))
