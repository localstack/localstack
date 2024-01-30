import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..KeyPairs..KeyType",
        "$..KeyPairs..Tags",
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
