from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestStringOperations:
    @markers.aws.validated
    def test_string_split(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [
            {"fst": " ", "snd": ","},
            {"fst": " , ", "snd": ","},
            {"fst": ", , ,", "snd": ","},
            {"fst": ",,,,", "snd": ","},
            {"fst": "1,2,3,4,5", "snd": ","},
            {"fst": "This.is+a,test=string", "snd": ".+,="},
        ]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.STRING_SPLIT,
            input_values,
        )

    @markers.aws.validated
    def test_string_split_context_object(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [
            (
                "Value1,Value2,Value3\n"
                "Value4,Value5,Value6\n"
                ",,,\n"
                "true,1,'HelloWorld'\n"
                "Null,None,\n"
                "   \n"
            )
        ]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.STRING_SPLIT_CONTEXT_OBJECT,
            input_values,
        )
