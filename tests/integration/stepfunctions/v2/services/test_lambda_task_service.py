import json

import pytest

from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
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
class TestTaskServiceLambda:
    def test_invoke(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            definition,
            exec_input,
        )
