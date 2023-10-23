import json

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestAwsSdk:
    @markers.aws.validated
    def test_invalid_secret_name(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_FAILED_SECRETSMANAGER_CREATE_SECRET)
        definition = json.dumps(template)
        exec_input = json.dumps({"Name": "Invalid Name", "SecretString": "HelloWorld"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_no_such_bucket(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_FAILED_S3_LIST_OBJECTS)
        definition = json.dumps(template)
        bucket_name = f"someNonexistentBucketName{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "someNonexistentBucketName"))
        exec_input = json.dumps({"Bucket": bucket_name})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @pytest.mark.skipif(
        condition=not is_aws_cloud(),
        reason="No parameters validation for dynamodb api calls being returned.",
    )
    @markers.snapshot.skip_snapshot_verify(paths=["$..cause"])
    @markers.aws.validated
    def test_dynamodb_invalid_param(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        dynamodb_create_table,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.dynamodb_api())

        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_DYNAMODB_PUT_ITEM)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"TableName": f"no_such_sfn_test_table_{short_uid()}", "Key": None, "Item": None}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..cause"])
    @markers.aws.validated
    def test_dynamodb_put_item_no_such_table(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.dynamodb_api())

        table_name = f"no_such_sfn_test_table_{short_uid()}"

        template = EHT.load_sfn_template(EHT.AWS_SDK_TASK_DYNAMODB_PUT_ITEM)
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
            sfn_snapshot,
            definition,
            exec_input,
        )
