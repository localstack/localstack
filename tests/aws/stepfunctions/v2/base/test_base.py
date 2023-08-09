import json

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from tests.aws.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.stepfunctions.utils import (
    create_and_record_events,
    create_and_record_execution,
    is_old_provider,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestSnfApi:
    @markers.aws.unknown
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
    @markers.aws.unknown
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
