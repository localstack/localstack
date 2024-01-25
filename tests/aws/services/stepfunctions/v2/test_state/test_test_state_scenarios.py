import json

from botocore.config import Config

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TCT,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestStateCaseScenarios:
    @staticmethod
    def _send_test_state_request(aws_client_factory, **kwargs):
        return aws_client_factory(
            config=Config(inject_host_prefix=is_aws_cloud()),
        ).stepfunctions.test_state(**kwargs)

    @markers.aws.validated
    def test_base_pass_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_pass_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_pass_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_base_result_pass_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_result_pass_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_result_pass_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.BASE_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Value": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_io_pass_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterResultSelector"
        ]
    )
    def test_io_pass_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterResultSelector"
        ]
    )
    def test_io_pass_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_io_result_pass_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states. It also prunes declared fields
            # such as InputPath and Parameters.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_io_result_pass_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states. It also prunes declared fields
            # such as InputPath and Parameters.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_io_result_pass_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = TCT.load_sfn_template(TCT.IO_RESULT_PASS_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "initialData": {"fieldFromInput": "value from input", "otherField": "other value"},
                "unrelatedData": {"someOtherField": 1234},
            }
        )

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_base_lambda_task_state_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_TASK_STATE)
        template["Resource"] = create_1_res["CreateFunctionResponse"]["FunctionArn"]
        definition = json.dumps(template)
        exec_input = json.dumps({"inputData": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_lambda_task_state_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_TASK_STATE)
        template["Resource"] = create_1_res["CreateFunctionResponse"]["FunctionArn"]
        definition = json.dumps(template)
        exec_input = json.dumps({"inputData": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generelisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    def test_base_lambda_task_state_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_TASK_STATE)
        template["Resource"] = create_1_res["CreateFunctionResponse"]["FunctionArn"]
        definition = json.dumps(template)
        exec_input = json.dumps({"inputData": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_base_lambda_task_state_info(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_base_lambda_task_state_debug(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    def test_base_lambda_task_state_trace(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TCT.load_sfn_template(TCT.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_output = self._send_test_state_request(
            aws_client_factory,
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

