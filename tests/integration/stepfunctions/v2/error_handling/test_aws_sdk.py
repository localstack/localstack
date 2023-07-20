import json

import pytest

from localstack.testing.pytest.marking import Markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.integration.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@Markers.snapshot.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestAwsSdk:
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
