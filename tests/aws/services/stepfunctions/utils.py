import json
import logging
import os
from typing import Callable, Final

from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.aws.api.stepfunctions import (
    CreateStateMachineOutput,
    ExecutionStatus,
    HistoryEventList,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


# For EXPRESS state machines, the deletion will happen eventually (usually less than a minute).
# Running executions may emit logs after DeleteStateMachine API is called.
_DELETION_TIMEOUT_SECS: Final[int] = 120


def is_legacy_provider():
    return (
        os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        and os.environ.get("PROVIDER_OVERRIDE_STEPFUNCTIONS") == "legacy"
    )


def is_not_legacy_provider():
    return not is_legacy_provider()


def await_no_state_machines_listed(stepfunctions_client):
    def _is_empty_state_machine_list():
        lst_resp = stepfunctions_client.list_state_machines()
        state_machines = lst_resp["stateMachines"]
        return not bool(state_machines)

    success = poll_condition(
        condition=_is_empty_state_machine_list,
        timeout=_DELETION_TIMEOUT_SECS,
        interval=1,
    )
    if not success:
        LOG.warning("Timed out whilst awaiting for listing to be empty.")


def _is_state_machine_listed(stepfunctions_client, state_machine_arn: str) -> bool:
    lst_resp = stepfunctions_client.list_state_machines()
    state_machines = lst_resp["stateMachines"]
    for state_machine in state_machines:
        if state_machine["stateMachineArn"] == state_machine_arn:
            return True
    return False


def _is_state_machine_version_listed(
    stepfunctions_client, state_machine_arn: str, state_machine_version_arn: str
) -> bool:
    lst_resp = stepfunctions_client.list_state_machine_versions(stateMachineArn=state_machine_arn)
    versions = lst_resp["stateMachineVersions"]
    for version in versions:
        if version["stateMachineVersionArn"] == state_machine_version_arn:
            return True
    return False


def await_state_machine_not_listed(stepfunctions_client, state_machine_arn: str):
    success = poll_condition(
        condition=lambda: not _is_state_machine_listed(stepfunctions_client, state_machine_arn),
        timeout=_DELETION_TIMEOUT_SECS,
        interval=1,
    )
    if not success:
        LOG.warning(f"Timed out whilst awaiting for listing to exclude '{state_machine_arn}'.")


def await_state_machine_listed(stepfunctions_client, state_machine_arn: str):
    success = poll_condition(
        condition=lambda: _is_state_machine_listed(stepfunctions_client, state_machine_arn),
        timeout=_DELETION_TIMEOUT_SECS,
        interval=1,
    )
    if not success:
        LOG.warning(f"Timed out whilst awaiting for listing to include '{state_machine_arn}'.")


def await_state_machine_version_not_listed(
    stepfunctions_client, state_machine_arn: str, state_machine_version_arn: str
):
    success = poll_condition(
        condition=lambda: not _is_state_machine_version_listed(
            stepfunctions_client, state_machine_arn, state_machine_version_arn
        ),
        timeout=_DELETION_TIMEOUT_SECS,
        interval=1,
    )
    if not success:
        LOG.warning(
            f"Timed out whilst awaiting for version of {state_machine_arn} to exclude '{state_machine_version_arn}'."
        )


def await_state_machine_version_listed(
    stepfunctions_client, state_machine_arn: str, state_machine_version_arn: str
):
    success = poll_condition(
        condition=lambda: _is_state_machine_version_listed(
            stepfunctions_client, state_machine_arn, state_machine_version_arn
        ),
        timeout=_DELETION_TIMEOUT_SECS,
        interval=1,
    )
    if not success:
        LOG.warning(
            f"Timed out whilst awaiting for version of {state_machine_arn} to include '{state_machine_version_arn}'."
        )


def _await_on_execution_events(
    stepfunctions_client, execution_arn: str, check_func: Callable[[HistoryEventList], bool]
) -> None:
    def _run_check():
        try:
            hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        except ClientError:
            return False
        events: HistoryEventList = sorted(
            hist_resp.get("events", []), key=lambda event: event.get("timestamp")
        )
        res: bool = check_func(events)
        return res

    success = poll_condition(condition=_run_check, timeout=120, interval=1)
    if not success:
        LOG.warning(
            f"Timed out whilst awaiting for execution events to satisfy condition for execution '{execution_arn}'."
        )


def await_execution_success(stepfunctions_client, execution_arn: str):
    def _check_last_is_success(events: HistoryEventList) -> bool:
        if len(events) > 0:
            last_event = events[-1]
            return "executionSucceededEventDetails" in last_event
        return False

    _await_on_execution_events(
        stepfunctions_client=stepfunctions_client,
        execution_arn=execution_arn,
        check_func=_check_last_is_success,
    )


def await_execution_terminated(stepfunctions_client, execution_arn: str):
    def _check_last_is_terminal(events: HistoryEventList) -> bool:
        if len(events) > 0:
            last_event = events[-1]
            last_event_type = last_event.get("type")
            return last_event_type is None or last_event_type in {
                HistoryEventType.ExecutionFailed,
                HistoryEventType.ExecutionAborted,
                HistoryEventType.ExecutionTimedOut,
                HistoryEventType.ExecutionSucceeded,
            }
        return False

    _await_on_execution_events(
        stepfunctions_client=stepfunctions_client,
        execution_arn=execution_arn,
        check_func=_check_last_is_terminal,
    )


def await_execution_lists_terminated(
    stepfunctions_client, state_machine_arn: str, execution_arn: str
):
    def _check_last_is_terminal() -> bool:
        list_output = stepfunctions_client.list_executions(stateMachineArn=state_machine_arn)
        executions = list_output["executions"]
        for execution in executions:
            if execution["executionArn"] == execution_arn:
                return execution["status"] != ExecutionStatus.RUNNING
        return False

    success = poll_condition(condition=_check_last_is_terminal, timeout=120, interval=1)
    if not success:
        LOG.warning(
            f"Timed out whilst awaiting for execution events to satisfy condition for execution '{execution_arn}'."
        )


def await_execution_started(stepfunctions_client, execution_arn: str):
    def _check_stated_exists(events: HistoryEventList) -> bool:
        for event in events:
            return "executionStartedEventDetails" in event
        return False

    _await_on_execution_events(
        stepfunctions_client=stepfunctions_client,
        execution_arn=execution_arn,
        check_func=_check_stated_exists,
    )


def await_execution_aborted(stepfunctions_client, execution_arn: str):
    def _run_check():
        desc_res = stepfunctions_client.describe_execution(executionArn=execution_arn)
        status: ExecutionStatus = desc_res["status"]
        return status == ExecutionStatus.ABORTED

    success = poll_condition(condition=_run_check, timeout=120, interval=1)
    if not success:
        LOG.warning(f"Timed out whilst awaiting for execution '{execution_arn}' to abort.")


def create(
    create_iam_role_for_sfn,
    create_state_machine,
    snapshot,
    definition,
):
    snf_role_arn = create_iam_role_for_sfn()
    snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
    snapshot.add_transformer(
        RegexTransformer(
            "Extended Request ID: [a-zA-Z0-9-/=+]+",
            "Extended Request ID: <extended_request_id>",
        )
    )
    snapshot.add_transformer(
        RegexTransformer("Request ID: [a-zA-Z0-9-]+", "Request ID: <request_id>")
    )

    sm_name: str = f"statemachine_create_and_record_execution_{short_uid()}"
    creation_resp = create_state_machine(name=sm_name, definition=definition, roleArn=snf_role_arn)
    snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
    state_machine_arn = creation_resp["stateMachineArn"]
    return state_machine_arn


def launch_and_record_execution(
    stepfunctions_client,
    sfn_snapshot,
    state_machine_arn,
    execution_input,
):
    exec_resp = stepfunctions_client.start_execution(
        stateMachineArn=state_machine_arn, input=execution_input
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
    execution_arn = exec_resp["executionArn"]

    await_execution_terminated(
        stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
    )

    get_execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)

    # Transform all map runs if any.
    try:
        map_run_arns = JSONPathUtils.extract_json("$..mapRunArn", get_execution_history)
        if isinstance(map_run_arns, str):
            map_run_arns = [map_run_arns]
        for i, map_run_arn in enumerate(list(set(map_run_arns))):
            sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_map_run_arn(map_run_arn, i))
    except RuntimeError:
        # No mapRunArns
        pass

    sfn_snapshot.match("get_execution_history", get_execution_history)


def create_and_record_execution(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    definition,
    execution_input,
):
    state_machine_arn = create(
        create_iam_role_for_sfn, create_state_machine, sfn_snapshot, definition
    )
    launch_and_record_execution(
        stepfunctions_client,
        sfn_snapshot,
        state_machine_arn,
        execution_input,
    )


def create_and_record_events(
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_events_to_sqs_queue,
    aws_client,
    sfn_snapshot,
    definition,
    execution_input,
):
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sqs_api())
    sfn_snapshot.add_transformers_list(
        [
            JsonpathTransformer(
                jsonpath="$..detail.startDate",
                replacement="start-date",
                replace_reference=False,
            ),
            JsonpathTransformer(
                jsonpath="$..detail.stopDate",
                replacement="stop-date",
                replace_reference=False,
            ),
            JsonpathTransformer(
                jsonpath="$..detail.name",
                replacement="test_event_bridge_events-{short_uid()}",
                replace_reference=False,
            ),
        ]
    )

    snf_role_arn = create_iam_role_for_sfn()
    create_output: CreateStateMachineOutput = create_state_machine(
        name=f"test_event_bridge_events-{short_uid()}",
        definition=definition,
        roleArn=snf_role_arn,
    )
    state_machine_arn = create_output["stateMachineArn"]

    queue_url = sfn_events_to_sqs_queue(state_machine_arn=state_machine_arn)

    start_execution = aws_client.stepfunctions.start_execution(
        stateMachineArn=state_machine_arn, input=execution_input
    )
    execution_arn = start_execution["executionArn"]
    await_execution_terminated(
        stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
    )

    stepfunctions_events = list()

    def _get_events():
        received = aws_client.sqs.receive_message(QueueUrl=queue_url)
        for message in received.get("Messages", []):
            body = json.loads(message["Body"])
            stepfunctions_events.append(body)
        stepfunctions_events.sort(key=lambda e: e["time"])
        return stepfunctions_events and stepfunctions_events[-1]["detail"]["status"] != "RUNNING"

    poll_condition(_get_events, timeout=60)

    sfn_snapshot.match("stepfunctions_events", stepfunctions_events)


def record_sqs_events(aws_client, queue_url, sfn_snapshot, num_events):
    stepfunctions_events = list()

    def _get_events():
        received = aws_client.sqs.receive_message(QueueUrl=queue_url)
        for message in received.get("Messages", []):
            body = json.loads(message["Body"])
            stepfunctions_events.append(body)
        stepfunctions_events.sort(key=lambda e: e["time"])
        return len(stepfunctions_events) == num_events

    poll_condition(_get_events, timeout=60)
    stepfunctions_events.sort(key=lambda e: json.dumps(e.get("detail", dict())))
    sfn_snapshot.match("stepfunctions_events", stepfunctions_events)
