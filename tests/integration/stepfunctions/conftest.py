import logging
from typing import Final

import pytest

from localstack.aws.api.stepfunctions import ExecutionStatus
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)

# For EXPRESS state machines, the deletion will happen eventually (usually less than a minute).
# Running executions may emit logs after DeleteStateMachine API is called.
_DELETION_TIMEOUT_SECS: Final[int] = 120


@pytest.fixture
def snf_snapshot(snapshot):
    return snapshot


@pytest.fixture
def create_iam_role_for_snf(create_iam_role_with_policy):
    role_name = f"test-snf-role-{short_uid()}"
    policy_name = f"test-lambda-policy-{short_uid()}"
    snf_role = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    snf_permission = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "lambda:*",
                    "sqs:*",
                    "dynamodb:*",
                    "secretsmanager:*",
                    "logs:*",
                ],
                "Resource": ["*"],
            }
        ],
    }

    def _create():
        return create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=snf_role,
            PolicyDefinition=snf_permission,
        )

    return _create


_state_machine_arns: Final[list[str]] = list()


@pytest.fixture
def create_state_machine(stepfunctions_client):
    def _create_state_machine(**kwargs):
        create_output = stepfunctions_client.create_state_machine(**kwargs)
        create_output_arn = create_output["stateMachineArn"]
        _state_machine_arns.append(create_output_arn)
        return create_output

    yield _create_state_machine

    for state_machine_arn in _state_machine_arns:
        try:
            stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)
        except Exception:
            LOG.debug(f"Unable to delete state machine '{state_machine_arn}' during cleanup.")


@pytest.fixture
def await_no_state_machines_listed(stepfunctions_client):
    def _exec_await():
        def _is_empty_state_machine_list():
            lst_resp = stepfunctions_client.list_state_machines()
            state_machines = lst_resp["stateMachines"]
            return not bool(state_machines)

        success = poll_condition(
            condition=_is_empty_state_machine_list,
            timeout=_DELETION_TIMEOUT_SECS,
            interval=5,
        )
        if not success:
            LOG.warning("Timed out whilst awaiting for listing to be empty.")

    return _exec_await


def _is_state_machine_listed(stepfunctions_client, state_machine_arn: str) -> bool:
    lst_resp = stepfunctions_client.list_state_machines()
    state_machines = lst_resp["stateMachines"]
    for state_machine in state_machines:
        if state_machine["stateMachineArn"] == state_machine_arn:
            return True
    return False


@pytest.fixture
def await_state_machine_not_listed(stepfunctions_client):
    def _exec_await(state_machine_arn: str):
        success = poll_condition(
            condition=lambda: not _is_state_machine_listed(stepfunctions_client, state_machine_arn),
            timeout=_DELETION_TIMEOUT_SECS,
            interval=5,
        )
        if not success:
            LOG.warning(f"Timed out whilst awaiting for listing to exclude '{state_machine_arn}'.")

    return _exec_await


@pytest.fixture
def await_state_machine_listed(stepfunctions_client):
    def _exec_await(state_machine_arn: str):
        success = poll_condition(
            condition=lambda: _is_state_machine_listed(stepfunctions_client, state_machine_arn),
            timeout=_DELETION_TIMEOUT_SECS,
            interval=5,
        )
        if not success:
            LOG.warning(f"Timed out whilst awaiting for listing to include '{state_machine_arn}'.")

    return _exec_await


def _await_last_execution_event_is(stepfunctions_client, event_key: str):
    def _exec_await(execution_anr: str):
        def _run_check():
            hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_anr)
            events = sorted(hist_resp.get("events", []), key=lambda event: event.get("timestamp"))
            if len(events) > 0:
                last_event = events[-1]
                return event_key in last_event
            return False

        success = poll_condition(condition=_run_check, timeout=120, interval=5)
        if not success:
            LOG.warning(
                f"Timed out whilst awaiting for execution events to end with a '{event_key}' event "
                f"for execution '{execution_anr}'."
            )

    return _exec_await


@pytest.fixture
def await_execution_success(stepfunctions_client):
    def _exec_await(execution_anr: str):
        def _run_check():
            hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_anr)
            events = sorted(hist_resp.get("events", []), key=lambda event: event.get("timestamp"))
            if len(events) > 0:
                last_event = events[-1]
                return "executionSucceededEventDetails" in last_event
            return False

        success = poll_condition(condition=_run_check, timeout=120, interval=5)
        if not success:
            LOG.warning(
                f"Timed out whilst awaiting for execution events to end with a executionSucceededEventDetails event "
                f"for execution '{execution_anr}'."
            )

    return _exec_await


@pytest.fixture
def await_execution_started(stepfunctions_client):
    def _exec_await(execution_anr: str):
        def _run_check():
            hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_anr)
            events = sorted(hist_resp.get("events", []), key=lambda event: event.get("timestamp"))
            for event in events:
                return "executionStartedEventDetails" in event
            return False

        success = poll_condition(condition=_run_check, timeout=120, interval=5)
        if not success:
            LOG.warning(
                f"Timed out whilst awaiting for execution events to end with a executionSucceededEventDetails event "
                f"for execution '{execution_anr}'."
            )

    return _exec_await


@pytest.fixture
def await_execution_aborted(stepfunctions_client):
    def _exec_await(execution_anr: str):
        def _run_check():
            desc_res = stepfunctions_client.describe_execution(executionArn=execution_anr)
            status: ExecutionStatus = desc_res["status"]
            return status == ExecutionStatus.ABORTED

        success = poll_condition(condition=_run_check, timeout=120, interval=5)
        if not success:
            LOG.warning(f"Timed out whilst awaiting for execution '{execution_anr}' to abort.")

    return _exec_await
