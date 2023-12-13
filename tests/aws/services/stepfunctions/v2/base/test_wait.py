import datetime
import json

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.utils import (
    create_and_record_execution,
)


# TODO: add tests for seconds, secondspath, timestamp
# TODO: add tests that actually validate waiting time (e.g. x minutes) BUT mark them accordingly and skip them by default!
@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestSfnWait:
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="not implemented")
    @markers.aws.validated
    @pytest.mark.parametrize("days", [24855, 24856])
    def test_timestamp_too_far_in_future_boundary(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, days
    ):
        """
        seems this seems to correlate with "2147483648" as the maximum integer value for the seconds stepfunctions internally uses to represent dates
        => 24855 days succeeds
        => 24856 days fails

        This isn't as important though since a statemachine can't run for more than a year anyway.
        Docs for Standard workflows: "If an execution runs for more than the 1-year maximum, it will fail with a States.Timeout error and emit a ExecutionsTimedOut CloudWatch metric."
        """
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_TIMESTAMPPATH)
        definition = json.dumps(template)

        wait_timestamp = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
            days=days
        )
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
            ".000000Z",
            ".00Z",
            # invalid formats
            "",
            ".000000",
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
        """
        - Timestamp needs to be in UTC (have a Z suffix)
        - Timestamp can be in the past (succeeds immediately)
        - Fractional seconds are optional and there's no specific number enforced (e.g. milliseconds vs. microseconds)
        """
        template = BaseTemplate.load_sfn_template(BaseTemplate.WAIT_TIMESTAMPPATH)
        definition = json.dumps(template)

        wait_timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
        timestamp = wait_timestamp.strftime("%Y-%m-%dT%H:%M:%S")

        full_timestamp = f"{timestamp}{timestamp_suffix}"
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
