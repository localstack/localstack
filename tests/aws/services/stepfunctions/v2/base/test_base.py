import datetime
import json
import re

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import JsonpathTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.utils import (
    await_execution_success,
    create_and_record_events,
    create_and_record_execution,
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

    @markers.aws.validated
    def test_state_pass_result_null_input_output_paths(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = BaseTemplate.load_sfn_template(BaseTemplate.PASS_RESULT_NULL_INPUT_OUTPUT_PATHS)
        definition = json.dumps(template)

        exec_input = json.dumps({"InputValue": 0})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_execution_dateformat(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
    ):
        """
        When returning timestamps as strings, StepFunctions uses a format like this:
        "2023-11-21T06:27:31.545Z"

        It's similar to the one used for Wait and Choice states but with the small difference of including milliseconds.

        It has 3-digit precision on the second (i.e. millisecond precision) and is *always* terminated by a Z.
        When testing, it seems to always return a UTC time zone (signaled by the Z character at the end).
        """
        template = BaseTemplate.load_sfn_template(BaseTemplate.PASS_START_TIME)
        definition = json.dumps(template)

        sm_name = f"test-dateformat-machine-{short_uid()}"
        sm = create_state_machine(
            name=sm_name, definition=definition, roleArn=create_iam_role_for_sfn()
        )

        sm_arn = sm["stateMachineArn"]
        execution = aws_client.stepfunctions.start_execution(stateMachineArn=sm_arn, input="{}")
        execution_arn = execution["executionArn"]
        await_execution_success(aws_client.stepfunctions, execution_arn)
        execution_done = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)

        # Since snapshots currently transform any timestamp-like value to a generic token,
        # we handle the assertions here manually

        # check that date format conforms to AWS spec e.g. "2023-11-21T06:27:31.545Z"
        date_regex = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z"
        context_start_time = json.loads(execution_done["output"])["out1"]
        assert re.match(date_regex, context_start_time)

        # make sure execution start time on the API side is the same as the one returned internally when accessing the context object
        d = execution_done["startDate"].astimezone(datetime.UTC)
        serialized_date = f'{d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]}Z'
        assert context_start_time == serialized_date
