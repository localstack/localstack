from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs


class TestJsonManipulationJSONata:
    @markers.aws.validated
    def test_parse(self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client):
        input_values = [
            # "null", TODO: Skip as this is failing on the $eval/$parse
            "-0",
            "1",
            "1.1",
            "true",
            '"HelloWorld"',
            '[1, 2, "HelloWorld"]',
            '{"Arg1": 1, "Arg2": []}',
        ]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.PARSE_JSONATA,
            input_values,
        )
