import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_state_machine_with_iam_role,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        # # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceDynamoDB:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            ST.DYNAMODB_PUT_GET_ITEM,
            ST.DYNAMODB_PUT_DELETE_ITEM,
            ST.DYNAMODB_PUT_UPDATE_GET_ITEM,
        ],
        ids=[
            "DYNAMODB_PUT_GET_ITEM",
            "DYNAMODB_PUT_DELETE_ITEM",
            "DYNAMODB_PUT_UPDATE_GET_ITEM",
        ],
    )
    def test_base_integrations(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        dynamodb_create_table,
        sfn_snapshot,
        template_path,
    ):
        table_name = f"sfn_test_table_{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key="id", client=aws_client.dynamodb)
        sfn_snapshot.add_transformer(RegexTransformer(table_name, "table-name"))

        template = ST.load_sfn_template(template_path)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
                "Key": {"id": {"S": "id1"}},
                "UpdateExpression": "set S=:r",
                "ExpressionAttributeValues": {":r": {"S": "HelloWorldUpdated"}},
            }
        )
        create_and_record_execution(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..exception_value"])
    def test_invalid_integration(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.INVALID_INTEGRATION_DYNAMODB_QUERY)
        definition = json.dumps(template)
        with pytest.raises(Exception) as ex:
            create_state_machine_with_iam_role(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
            )
        sfn_snapshot.match(
            "exception", {"exception_typename": ex.typename, "exception_value": ex.value}
        )
