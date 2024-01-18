import json

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate as BT
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create, create_and_record_execution


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceAwsSdk:
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecretList"])
    @markers.aws.validated
    def test_list_secrets(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        template = ST.load_sfn_template(ST.AWSSDK_LIST_SECRETS)
        definition = json.dumps(template)
        exec_input = json.dumps(dict())
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_dynamodb_put_get_item(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        dynamodb_create_table,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        table_name = f"sfn_test_table_{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key="id", client=aws_client.dynamodb)

        template = ST.load_sfn_template(ST.AWS_SDK_DYNAMODB_PUT_GET_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
                "Key": {"id": {"S": "id1"}},
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

    @markers.aws.validated
    def test_dynamodb_put_delete_item(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        dynamodb_create_table,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        table_name = f"sfn_test_table_{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key="id", client=aws_client.dynamodb)

        template = ST.load_sfn_template(ST.AWS_SDK_DYNAMODB_PUT_DELETE_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
                "Key": {"id": {"S": "id1"}},
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

    @markers.aws.validated
    def test_dynamodb_put_update_get_item(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        dynamodb_create_table,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.dynamodb_api())

        table_name = f"sfn_test_table_{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key="id", client=aws_client.dynamodb)

        template = ST.load_sfn_template(ST.AWS_SDK_DYNAMODB_PUT_UPDATE_GET_ITEM)
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
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_sfn_start_execution(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template_target = BT.load_sfn_template(BT.BASE_RAISE_FAILURE)
        definition_target = json.dumps(template_target)
        state_machine_arn_target = create(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition_target,
        )

        template = ST.load_sfn_template(ST.AWS_SDK_SFN_START_EXECUTION)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"StateMachineArn": state_machine_arn_target, "Input": None, "Name": "TestStartTarget"}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
