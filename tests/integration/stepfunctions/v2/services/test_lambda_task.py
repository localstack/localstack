import json

import pytest

from localstack.testing.pytest.marking import Markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.lambda_functions import lambda_functions
from tests.integration.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.integration.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@Markers.snapshot.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestTaskLambda:
    def test_invoke_pipe(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_1_name = f"lambda_1_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_1_name,
            handler_file=lambda_functions.ECHO_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_1_name, "<lambda_function_1_name>"))

        function_2_name = f"lambda_2_func_{short_uid()}"
        create_2_res = create_lambda_function(
            func_name=function_2_name,
            handler_file=lambda_functions.ECHO_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_2_name, "<lambda_function_2_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE_PIPE)
        template["States"]["step1"]["Resource"] = create_1_res["CreateFunctionResponse"][
            "FunctionArn"
        ]
        template["States"]["step2"]["Resource"] = create_2_res["CreateFunctionResponse"][
            "FunctionArn"
        ]
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
