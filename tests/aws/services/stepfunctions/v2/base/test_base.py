import json

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import JsonpathTransformer
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.utils import (
    create_and_record_events,
    create_and_record_execution,
    is_old_provider,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestSnfBase:
    @markers.aws.validated
    def test_state_fail(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_RAISE_FAILURE)
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
    def test_state_fail_empty(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.RAISE_EMPTY_FAILURE)
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
    def test_state_pass_result(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
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
    def test_state_pass_result_jsonpaths(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_PASS_RESULT)
        template["States"]["State_1"]["Result"] = {
            "unsupported1.$": "$.jsonpath",
            "unsupported2.$": "$$",
        }
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
    def test_event_bridge_events_base(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_events_to_sqs_queue,
        aws_client,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.BASE_WAIT_1_MIN)
        template["States"]["State_1"]["Seconds"] = 60 if is_aws_cloud() else 1
        definition = json.dumps(template)
        execution_input = json.dumps(dict())
        create_and_record_events(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_events_to_sqs_queue,
            aws_client,
            sfn_snapshot,
            definition,
            execution_input,
        )

    @pytest.mark.skip(reason="flaky")  # FIXME
    @markers.aws.needs_fixing
    def test_event_bridge_events_failure(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_events_to_sqs_queue,
        aws_client,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_AND_FAIL)
        template["States"]["State_1"]["Seconds"] = 60 if is_aws_cloud() else 1
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_events(
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_events_to_sqs_queue,
            aws_client,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_query_context_object_values(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        aws_client,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StartTime", replacement="start-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..execution_starttime", replacement="start-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..EnteredTime", replacement="entered-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..state_enteredtime", replacement="entered-time", replace_reference=False
            )
        )

        template = BaseTemplate.load_sfn_template(BaseTemplate.QUERY_CONTEXT_OBJECT_VALUES)
        definition = json.dumps(template)

        exec_input = json.dumps({"message": "HelloWorld!"})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
