import json

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
    create_and_record_mocked_execution,
    create_state_machine_with_iam_role,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.mocked_service_integrations.mocked_service_integrations import (
    MockedServiceIntegrationsLoader,
)
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.templates.callbacks.callback_templates import (
    CallbackTemplates,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        "$..ExecutedVersion",
        "$..RedriveCount",
        "$..RedriveStatus",
        "$..RedriveStatusReason",
        # In an effort to comply with SFN Local's lack of handling of sync operations,
        # we are unable to produce valid TaskSubmittedEventDetails output field, which
        # must include the provided mocked response in the output:
        "$..events..taskSubmittedEventDetails.output",
    ]
)
class TestBaseScenarios:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_file_path, mocked_response_filepath",
        [
            (
                CallbackTemplates.SFN_START_EXECUTION_SYNC,
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC,
            ),
            (
                CallbackTemplates.SFN_START_EXECUTION_SYNC2,
                MockedServiceIntegrationsLoader.MOCKED_RESPONSE_STATES_200_START_EXECUTION_SYNC2,
            ),
        ],
        ids=["SFN_SYNC", "SFN_SYNC2"],
    )
    def test_sfn_start_execution_sync(
        self,
        aws_client,
        create_state_machine_iam_role,
        create_state_machine,
        monkeypatch,
        mock_config_file,
        sfn_snapshot,
        template_file_path,
        mocked_response_filepath,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output.StopDate",
                replacement="stop-date",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StateMachineArn",
                replacement="state-machine-arn",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..ExecutionArn",
                replacement="execution-arn",
                replace_reference=False,
            )
        )

        template = CallbackTemplates.load_sfn_template(template_file_path)
        definition = json.dumps(template)

        if is_aws_cloud():
            template_target = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
            definition_target = json.dumps(template_target)
            state_machine_arn_target = create_state_machine_with_iam_role(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition_target,
            )

            exec_input = json.dumps(
                {
                    "StateMachineArn": state_machine_arn_target,
                    "Input": None,
                    "Name": "TestStartTarget",
                }
            )
            create_and_record_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
            )
        else:
            state_machine_name = f"mocked_state_machine_{short_uid()}"
            test_name = "TestCaseName"
            mocked_response = MockedServiceIntegrationsLoader.load(mocked_response_filepath)
            mock_config = {
                "StateMachines": {
                    state_machine_name: {
                        "TestCases": {test_name: {"StartExecution": "mocked_response"}}
                    }
                },
                "MockedResponses": {"mocked_response": mocked_response},
            }
            mock_config_file_path = mock_config_file(mock_config)
            monkeypatch.setattr(config, "SFN_MOCK_CONFIG", mock_config_file_path)
            exec_input = json.dumps(
                {"StateMachineArn": "state-machine-arn", "Input": None, "Name": "TestStartTarget"}
            )
            create_and_record_mocked_execution(
                aws_client,
                create_state_machine_iam_role,
                create_state_machine,
                sfn_snapshot,
                definition,
                exec_input,
                state_machine_name,
                test_name,
            )
