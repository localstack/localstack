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
    # TODO: timestamp in the past
    # def test_timestamp_in_past(self):

    # TODO: test maximum wait time (1 year and 5 minutes)
    # def test_timestamp_too_far_in_future(self):

    @pytest.mark.parametrize(
        "timestamp_suffix",
        [
            # valid formats
            # TODO: re-enable
            # "Z",
            # ".000000Z",
            # ".000Z",
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
        exec_input = json.dumps({"start_at": f"{timestamp}{timestamp_suffix}"})
        # TODO: make this return the execution ARN for manual assertions
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
