import json

import pytest
from botocore.config import Config

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
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
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_pass(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        inspection_level,
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
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_result_pass(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        inspection_level,
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
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_io_pass(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        inspection_level,
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
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_output", test_case_output)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_io_result_pass(
        self,
        aws_client_factory,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        inspection_level,
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
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_output", test_case_output)
