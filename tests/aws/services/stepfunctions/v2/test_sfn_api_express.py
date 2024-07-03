import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.stepfunctions import StateMachineType
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_express_async_execution,
    create_and_record_express_sync_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.templates.services.services_templates import ServicesTemplates


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        "$..billingDetails",
        "$..redrive_count",
        "$..event_timestamp",
    ]
)
class TestSfnApiExpress:
    @markers.aws.validated
    def test_create_describe_delete(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        aws_client,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        definition = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)

        creation_response = create_state_machine(
            name=f"statemachine_{short_uid()}",
            definition=definition_str,
            roleArn=snf_role_arn,
            type=StateMachineType.EXPRESS,
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))
        sfn_snapshot.match("creation_response", creation_response)

        state_machine_arn = creation_response["stateMachineArn"]
        describe_response = aws_client.stepfunctions.describe_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("describe_response", describe_response)

        deletion_response = aws_client.stepfunctions.delete_state_machine(
            stateMachineArn=state_machine_arn
        )
        sfn_snapshot.match("deletion_response", deletion_response)

    @markers.aws.validated
    def test_start_async_describe_history_execution(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_create_log_group,
        sfn_snapshot,
        aws_client,
    ):
        definition = ServicesTemplates.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition_str = json.dumps(definition)
        execution_input = json.dumps(dict())
        state_machine_arn, execution_arn = create_and_record_express_async_execution(
            aws_client,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_create_log_group,
            sfn_snapshot,
            definition_str,
            execution_input,
        )

        with pytest.raises(Exception) as ex:
            aws_client.stepfunctions.list_executions(stateMachineArn=state_machine_arn)
        sfn_snapshot.match("list_executions_error", ex.value.response)

        with pytest.raises(Exception) as ex:
            aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("describe_execution_error", ex.value.response)

        with pytest.raises(Exception) as ex:
            aws_client.stepfunctions.stop_execution(executionArn=execution_arn)
        sfn_snapshot.match("stop_execution_error", ex.value.response)

        with pytest.raises(Exception) as ex:
            aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match("get_execution_history_error", ex.value.response)

    @markers.aws.validated
    def test_start_sync_execution(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
        stepfunctions_client_sync_executions,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_express_sync_execution(
            stepfunctions_client_sync_executions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
