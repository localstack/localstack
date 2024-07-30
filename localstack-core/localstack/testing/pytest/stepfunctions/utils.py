import json
import logging
import os
from typing import Callable, Final, Optional

from botocore.exceptions import ClientError
from jsonpath_ng.ext import parse
from localstack_snapshot.snapshots.transformer import (
    JsonpathTransformer,
    RegexTransformer,
    TransformContext,
)

from localstack.aws.api.stepfunctions import (
    CloudWatchLogsLogGroup,
    CreateStateMachineOutput,
    Definition,
    ExecutionStatus,
    HistoryEventList,
    HistoryEventType,
    LogDestination,
    LoggingConfiguration,
    LogLevel,
    LongArn,
    StateMachineType,
)
from localstack.services.stepfunctions.asl.eval.event.logging import is_logging_enabled_for
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


# For EXPRESS state machines, the deletion will happen eventually (usually less than a minute).
# Running executions may emit logs after DeleteStateMachine API is called.
_DELETION_TIMEOUT_SECS: Final[int] = 120


def is_legacy_provider():
    return not is_aws_cloud() and os.environ.get("PROVIDER_OVERRIDE_STEPFUNCTIONS") == "legacy"


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


def await_on_execution_events(
    stepfunctions_client, execution_arn: str, check_func: Callable[[HistoryEventList], bool]
) -> HistoryEventList:
    events: HistoryEventList = list()

    def _run_check():
        nonlocal events
        events.clear()
        try:
            hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        except ClientError:
            return False
        events.extend(sorted(hist_resp.get("events", []), key=lambda event: event.get("timestamp")))
        res: bool = check_func(events)
        return res

    assert poll_condition(condition=_run_check, timeout=120, interval=1)
    return events


def await_execution_success(stepfunctions_client, execution_arn: str) -> HistoryEventList:
    def _check_last_is_success(events: HistoryEventList) -> bool:
        if len(events) > 0:
            last_event = events[-1]
            return "executionSucceededEventDetails" in last_event
        return False

    return await_on_execution_events(
        stepfunctions_client=stepfunctions_client,
        execution_arn=execution_arn,
        check_func=_check_last_is_success,
    )


def await_list_execution_status(
    stepfunctions_client, state_machine_arn: str, execution_arn: str, status: str
):
    """required as there is some eventual consistency in list_executions vs describe_execution and get_execution_history"""

    def _run_check():
        list_resp = stepfunctions_client.list_executions(
            stateMachineArn=state_machine_arn, statusFilter=status
        )
        for execution in list_resp.get("executions", []):
            if execution["executionArn"] != execution_arn or execution["status"] != status:
                continue
            return True
        return False

    success = poll_condition(condition=_run_check, timeout=120, interval=1)
    if not success:
        LOG.warning(
            f"Timed out whilst awaiting for execution status {status} to satisfy condition for execution '{execution_arn}'."
        )


def _is_last_history_event_terminal(events: HistoryEventList) -> bool:
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


def await_execution_terminated(stepfunctions_client, execution_arn: str) -> HistoryEventList:
    return await_on_execution_events(
        stepfunctions_client=stepfunctions_client,
        execution_arn=execution_arn,
        check_func=_is_last_history_event_terminal,
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


def await_execution_started(stepfunctions_client, execution_arn: str) -> HistoryEventList:
    def _check_stated_exists(events: HistoryEventList) -> bool:
        for event in events:
            return "executionStartedEventDetails" in event
        return False

    return await_on_execution_events(
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


def get_expected_execution_logs(
    stepfunctions_client, log_level: LogLevel, execution_arn: LongArn
) -> HistoryEventList:
    execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)
    execution_history_events = execution_history["events"]
    expected_events = [
        event
        for event in execution_history_events
        if is_logging_enabled_for(log_level=log_level, history_event_type=event["type"])
    ]
    return expected_events


def is_execution_logs_list_complete(
    expected_events: HistoryEventList,
) -> Callable[[HistoryEventList], bool]:
    def _validation_function(log_events: list) -> bool:
        if not expected_events:
            return True
        return len(expected_events) == len(log_events)

    return _validation_function


def _await_on_execution_log_stream_created(aws_client, log_group_name: str) -> str:
    logs_client = aws_client.logs
    log_stream_name = str()

    def _run_check():
        nonlocal log_stream_name
        try:
            log_streams = logs_client.describe_log_streams(logGroupName=log_group_name)[
                "logStreams"
            ]
            if not log_streams:
                return False

            log_stream_name = log_streams[-1]["logStreamName"]
            if (
                log_stream_name
                == "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"
            ):
                # SFN has not yet create the log stream for the execution, only the validation steam.
                return False
            return True
        except ClientError:
            return False

    assert poll_condition(condition=_run_check)
    return log_stream_name


def await_on_execution_logs(
    aws_client,
    log_group_name: str,
    validation_function: Callable[[HistoryEventList], bool] = None,
) -> HistoryEventList:
    log_stream_name = _await_on_execution_log_stream_created(aws_client, log_group_name)

    logs_client = aws_client.logs
    events: HistoryEventList = list()

    def _run_check():
        nonlocal events
        events.clear()
        try:
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name, startFromHead=True
            )["events"]
            events.extend([json.loads(e["message"]) for e in log_events])
        except ClientError:
            return False

        res = validation_function(events)
        return res

    assert poll_condition(condition=_run_check)
    return events


def create(
    create_iam_role_for_sfn,
    create_state_machine,
    snapshot,
    definition: Definition,
    logging_configuration: Optional[LoggingConfiguration] = None,
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
    create_arguments = {
        "name": sm_name,
        "definition": definition,
        "roleArn": snf_role_arn,
    }
    if logging_configuration is not None:
        create_arguments["loggingConfiguration"] = logging_configuration
    creation_resp = create_state_machine(**create_arguments)
    snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
    state_machine_arn = creation_resp["stateMachineArn"]
    return state_machine_arn


def launch_and_record_execution(
    stepfunctions_client,
    sfn_snapshot,
    state_machine_arn,
    execution_input,
    verify_execution_description=False,
) -> LongArn:
    exec_resp = stepfunctions_client.start_execution(
        stateMachineArn=state_machine_arn, input=execution_input
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
    execution_arn = exec_resp["executionArn"]

    await_execution_terminated(
        stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
    )

    if verify_execution_description:
        describe_execution = stepfunctions_client.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("describe_execution", describe_execution)

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

    return execution_arn


def launch_and_record_logs(
    aws_client,
    state_machine_arn,
    execution_input,
    log_level,
    log_group_name,
    sfn_snapshot,
):
    execution_arn = launch_and_record_execution(
        aws_client.stepfunctions,
        sfn_snapshot,
        state_machine_arn,
        execution_input,
    )
    expected_events = get_expected_execution_logs(
        aws_client.stepfunctions, log_level, execution_arn
    )

    if log_level == LogLevel.OFF or not expected_events:
        # The test should terminate here, as no log streams for this execution would have been created.
        return

    logs_validation_function = is_execution_logs_list_complete(expected_events)
    logged_execution_events = await_on_execution_logs(
        aws_client, log_group_name, logs_validation_function
    )

    sfn_snapshot.add_transformer(
        JsonpathTransformer(
            jsonpath="$..event_timestamp",
            replacement="timestamp",
            replace_reference=False,
        )
    )
    sfn_snapshot.match("logged_execution_events", logged_execution_events)


# TODO: make this return the execution ARN for manual assertions
def create_and_record_execution(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    definition,
    execution_input,
    verify_execution_description=False,
):
    state_machine_arn = create(
        create_iam_role_for_sfn, create_state_machine, sfn_snapshot, definition
    )
    launch_and_record_execution(
        stepfunctions_client,
        sfn_snapshot,
        state_machine_arn,
        execution_input,
        verify_execution_description,
    )


def create_and_record_logs(
    aws_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_create_log_group,
    sfn_snapshot,
    definition,
    execution_input,
    log_level: LogLevel,
    include_execution_data: bool,
):
    state_machine_arn = create(
        create_iam_role_for_sfn, create_state_machine, sfn_snapshot, definition
    )

    log_group_name = sfn_create_log_group()
    log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
        "logGroups"
    ][0]["arn"]
    logging_configuration = LoggingConfiguration(
        level=log_level,
        includeExecutionData=include_execution_data,
        destinations=[
            LogDestination(
                cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
            ),
        ],
    )
    aws_client.stepfunctions.update_state_machine(
        stateMachineArn=state_machine_arn, loggingConfiguration=logging_configuration
    )

    launch_and_record_logs(
        aws_client, state_machine_arn, execution_input, log_level, log_group_name, sfn_snapshot
    )


def launch_and_record_sync_execution(
    stepfunctions_client,
    sfn_snapshot,
    state_machine_arn,
    execution_input,
):
    exec_resp = stepfunctions_client.start_sync_execution(
        stateMachineArn=state_machine_arn,
        input=execution_input,
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_sync_exec_arn(exec_resp, 0))
    sfn_snapshot.match("start_execution_sync_response", exec_resp)


def create_and_record_express_sync_execution(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    definition,
    execution_input,
):
    snf_role_arn = create_iam_role_for_sfn()
    sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "sfn_role_arn"))

    creation_response = create_state_machine(
        name=f"express_statemachine_{short_uid()}",
        definition=definition,
        roleArn=snf_role_arn,
        type=StateMachineType.EXPRESS,
    )
    state_machine_arn = creation_response["stateMachineArn"]
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))
    sfn_snapshot.match("creation_response", creation_response)

    launch_and_record_sync_execution(
        stepfunctions_client,
        sfn_snapshot,
        state_machine_arn,
        execution_input,
    )


def launch_and_record_express_async_execution(
    aws_client,
    sfn_snapshot,
    state_machine_arn,
    log_group_name,
    execution_input,
):
    start_execution = aws_client.stepfunctions.start_execution(
        stateMachineArn=state_machine_arn, input=execution_input
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_express_exec_arn(start_execution, 0))
    execution_arn = start_execution["executionArn"]

    event_list = await_on_execution_logs(
        aws_client, log_group_name, validation_function=_is_last_history_event_terminal
    )
    # Snapshot only the end event, as AWS StepFunctions implements a flaky approach to logging previous events.
    end_event = event_list[-1]
    sfn_snapshot.match("end_event", end_event)

    return execution_arn


def create_and_record_express_async_execution(
    aws_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_create_log_group,
    sfn_snapshot,
    definition,
    execution_input,
    include_execution_data: bool = True,
) -> tuple[LongArn, LongArn]:
    snf_role_arn = create_iam_role_for_sfn()
    sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "sfn_role_arn"))

    log_group_name = sfn_create_log_group()
    log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
        "logGroups"
    ][0]["arn"]
    logging_configuration = LoggingConfiguration(
        level=LogLevel.ALL,
        includeExecutionData=include_execution_data,
        destinations=[
            LogDestination(
                cloudWatchLogsLogGroup=CloudWatchLogsLogGroup(logGroupArn=log_group_arn)
            ),
        ],
    )

    creation_response = create_state_machine(
        name=f"express_statemachine_{short_uid()}",
        definition=definition,
        roleArn=snf_role_arn,
        type=StateMachineType.EXPRESS,
        loggingConfiguration=logging_configuration,
    )
    state_machine_arn = creation_response["stateMachineArn"]
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_response, 0))
    sfn_snapshot.match("creation_response", creation_response)

    execution_arn = launch_and_record_express_async_execution(
        aws_client,
        sfn_snapshot,
        state_machine_arn,
        log_group_name,
        execution_input,
    )
    return state_machine_arn, execution_arn


def create_and_record_events(
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_events_to_sqs_queue,
    aws_client,
    sfn_snapshot,
    definition,
    execution_input,
):
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sqs_integration())
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


class SfnNoneRecursiveParallelTransformer:
    """
    Normalises a sublist of events triggered in by a Parallel state to be order-independent.
    """

    def __init__(self, events_jsonpath: str = "$..events"):
        self.events_jsonpath: str = events_jsonpath

    @staticmethod
    def _normalise_events(events: list[dict]) -> None:
        start_idx = None
        sublist = list()
        in_sublist = False
        for i, event in enumerate(events):
            event_type = event.get("type")
            if event_type is None:
                LOG.debug(f"No 'type' in event item '{event}'.")
                in_sublist = False

            elif event_type in {
                None,
                HistoryEventType.ParallelStateSucceeded,
                HistoryEventType.ParallelStateAborted,
                HistoryEventType.ParallelStateExited,
                HistoryEventType.ParallelStateFailed,
            }:
                events[start_idx:i] = sorted(sublist, key=lambda e: to_json_str(e))
                in_sublist = False
            elif event_type == HistoryEventType.ParallelStateStarted:
                in_sublist = True
                sublist = []
                start_idx = i + 1
            elif in_sublist:
                event["id"] = (0,)
                event["previousEventId"] = 0
                sublist.append(event)

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse("$..events")
        events = pattern.find(input_data)
        if not events:
            LOG.debug(f"No Stepfunctions 'events' for jsonpath '{self.events_jsonpath}'.")
            return input_data

        for events_data in events:
            self._normalise_events(events_data.value)

        return input_data
