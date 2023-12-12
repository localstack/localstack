import datetime
import json

import pytest

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.utils import (
    create_and_record_execution,
)


# TODO: add tests for seconds, secondspath, timestamp
@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestSfnWait:
    @markers.aws.unknown
    def test_timestamp_in_past_succeeds_immediately(
            self,
            aws_client,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_TIMESTAMPPATH)
        definition = json.dumps(template)

        offset_2days = datetime.timedelta(days=2)
        wait_timestamp = datetime.datetime.now(tz=datetime.timezone.utc) - offset_2days
        timestamp = wait_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

        full_timestamp = f"{timestamp}.000Z"
        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(full_timestamp, "<timestamp>"))
        exec_input = json.dumps({"start_at": full_timestamp})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )


    # TODO: test maximum wait time (1 year and 5 minutes)
    @markers.aws.unknown
    def test_timestamp_too_far_in_future_fails(
            self,
            aws_client,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_TIMESTAMPPATH)
        definition = json.dumps(template)

        offset_toofar = datetime.timedelta(days=800)
        wait_timestamp = datetime.datetime.now(tz=datetime.timezone.utc) + offset_toofar
        timestamp = wait_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

        full_timestamp = f"{timestamp}.000Z"
        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(full_timestamp, "<timestamp>"))
        exec_input = json.dumps({"start_at": full_timestamp})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )


    @pytest.mark.parametrize(
        "timestamp_suffix",
        [
            # valid formats
            "Z",
            ".0000000Z",
            ".000000Z",
            ".000Z",
            ".00Z",
            # invalid formats
            "",
            ".000000",
            ".000",
        ],
    )
    @markers.aws.validated
    def test_wait_timestamppath(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        timestamp_suffix,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_TIMESTAMPPATH)
        definition = json.dumps(template)

        offset_1min = datetime.timedelta(minutes=1)
        wait_timestamp = datetime.datetime.now(tz=datetime.timezone.utc) + offset_1min
        timestamp = wait_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

        full_timestamp = f"{timestamp}{timestamp_suffix}"
        sfn_snapshot.add_transformer(sfn_snapshot.transform.regex(full_timestamp, "<timestamp>"))
        exec_input = json.dumps({"start_at": full_timestamp})
        # TODO: make this return the execution ARN for manual assertions
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
