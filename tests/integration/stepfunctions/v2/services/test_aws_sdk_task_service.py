import json

import pytest

from tests.integration.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.integration.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        "$..previousEventId",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceAwsSdk:
    @pytest.mark.skip_snapshot_verify(paths=["$..SecretList"])
    def test_list_secrets(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        template = ST.load_sfn_template(ST.AWSSDK_LIST_SECRETS)
        definition = json.dumps(template)
        exec_input = json.dumps(dict())
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )
