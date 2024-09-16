import json

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        # TODO: review LS's dynamodb error messages.
        "$..Cause",
        "$..cause",
    ]
)
class TestTaskServiceDynamoDB:
    @markers.aws.validated
    def test_invalid_param(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        dynamodb_create_table,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_DYNAMODB_PUT_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"TableName": f"no_such_sfn_test_table_{short_uid()}", "Key": None, "Item": None}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_put_item_no_such_table(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        table_name = f"no_such_sfn_test_table_{short_uid()}"

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_DYNAMODB_PUT_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..error"  # TODO: LS returns a ResourceNotFoundException instead of reflecting the validation error
        ]
    )
    @markers.aws.validated
    def test_put_item_invalid_table_name(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        table_name = f"/invalid_test_table_{short_uid()}"

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_DYNAMODB_PUT_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )
