import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_execution
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.comment.comment_templates import (
    CommentTemplates as CT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestComments:
    @markers.aws.validated
    def test_comments_as_per_docs(
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
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_1_name, "lambda_function_1_name"))

        template = CT.load_sfn_template(CT.COMMENTS_AS_PER_DOCS)
        template["States"]["TaskStateCatchRetry"]["Resource"] = create_1_res[
            "CreateFunctionResponse"
        ]["FunctionArn"]
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

    @markers.aws.validated
    def test_comment_in_parameters(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = CT.load_sfn_template(CT.COMMENT_IN_PARAMETERS)
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
