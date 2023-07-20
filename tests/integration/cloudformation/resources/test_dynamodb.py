import os

import pytest

from localstack.testing.pytest.marking import Markers
from localstack.utils.strings import short_uid


def test_deploy_stack_with_dynamodb_table(deploy_cfn_template, aws_client):
    env = "Staging"
    ddb_table_name_prefix = f"ddb-table-{short_uid()}"
    ddb_table_name = f"{ddb_table_name_prefix}-{env}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/deploy_template_3.yaml"
        ),
        parameters={"tableName": ddb_table_name_prefix, "env": env},
    )

    assert stack.outputs["Arn"].startswith("arn:aws:dynamodb")
    assert f"table/{ddb_table_name}" in stack.outputs["Arn"]
    assert stack.outputs["Name"] == ddb_table_name

    rs = aws_client.dynamodb.list_tables()
    assert ddb_table_name in rs["TableNames"]

    stack.destroy()

    rs = aws_client.dynamodb.list_tables()
    assert ddb_table_name not in rs["TableNames"]


def test_globalindex_read_write_provisioned_throughput_dynamodb_table(
    deploy_cfn_template, aws_client
):
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/deploy_template_3.yaml"
        ),
        parameters={"tableName": "dynamodb", "env": "test"},
    )

    response = aws_client.dynamodb.describe_table(TableName="dynamodb-test")

    if response["Table"]["ProvisionedThroughput"]:
        throughput = response["Table"]["ProvisionedThroughput"]
        assert isinstance(throughput["ReadCapacityUnits"], int)
        assert isinstance(throughput["WriteCapacityUnits"], int)

    for global_index in response["Table"]["GlobalSecondaryIndexes"]:
        index_provisioned = global_index["ProvisionedThroughput"]
        test_read_capacity = index_provisioned["ReadCapacityUnits"]
        test_write_capacity = index_provisioned["WriteCapacityUnits"]
        assert isinstance(test_read_capacity, int)
        assert isinstance(test_write_capacity, int)


@Markers.parity.aws_validated
@Markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
        "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
        "$..Table.Replicas",
    ]
)
def test_default_name_for_table(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.dynamodb_api())
    snapshot.add_transformer(snapshot.transform.key_value("TableName", "table-name"))
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/dynamodb_table_defaults.yml"
        ),
    )

    response = aws_client.dynamodb.describe_table(TableName=stack.outputs["TableName"])
    snapshot.match("table_description", response)


@Markers.parity.aws_validated
@Markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
        "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
        "$..Table.Replicas",
        "$..Table.DeletionProtectionEnabled",
        "$..Table.LatestStreamArn",
        "$..Table.LatestStreamLabel",
    ]
)
@pytest.mark.parametrize("billing_mode", ["PROVISIONED", "PAY_PER_REQUEST"])
def test_billing_mode_as_conditional(deploy_cfn_template, snapshot, aws_client, billing_mode):
    snapshot.add_transformer(snapshot.transform.dynamodb_api())
    snapshot.add_transformer(snapshot.transform.key_value("TableName", "table-name"))
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/dynamodb_billing_conditional.yml"
        ),
        parameters={"BillingModeParameter": billing_mode},
    )

    response = aws_client.dynamodb.describe_table(TableName=stack.outputs["TableName"])
    snapshot.match("table_description", response)
