import json
from collections import defaultdict
from typing import Callable

import pytest

from localstack.aws.api.cloudformation import DescribeChangeSetOutput, StackEvent
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.utils.functions import call_safe
from localstack.utils.strings import short_uid

PerResourceStackEvents = dict[str, list[StackEvent]]


@pytest.fixture
def capture_per_resource_events(
    aws_client: ServiceLevelClientFactory,
) -> Callable[[str], PerResourceStackEvents]:
    def capture(stack_name: str) -> PerResourceStackEvents:
        events = aws_client.cloudformation.describe_stack_events(StackName=stack_name)[
            "StackEvents"
        ]
        per_resource_events = defaultdict(list)
        for event in events:
            if logical_resource_id := event.get("LogicalResourceId"):
                per_resource_events[logical_resource_id].append(event)
        return per_resource_events

    return capture


def _normalise_describe_change_set_output(value: DescribeChangeSetOutput) -> None:
    value.get("Changes", list()).sort(
        key=lambda change: change.get("ResourceChange", dict()).get("LogicalResourceId", str())
    )


@pytest.fixture
def capture_update_process(aws_client_no_retry, cleanups, capture_per_resource_events):
    """
    Fixture to deploy a new stack (via creating and executing a change set), then updating the
    stack with a second template (via creating and executing a change set).
    """

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"cs-{short_uid()}"

    def inner(
        snapshot, t1: dict | str, t2: dict | str, p1: dict | None = None, p2: dict | None = None
    ):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())

        if isinstance(t1, dict):
            t1 = json.dumps(t1)
        elif isinstance(t1, str):
            with open(t1) as infile:
                t1 = infile.read()
        if isinstance(t2, dict):
            t2 = json.dumps(t2)
        elif isinstance(t2, str):
            with open(t2) as infile:
                t2 = infile.read()

        p1 = p1 or {}
        p2 = p2 or {}

        # deploy original stack
        change_set_details = aws_client_no_retry.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=t1,
            ChangeSetType="CREATE",
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for (k, v) in p1.items()],
        )
        snapshot.match("create-change-set-1", change_set_details)
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client_no_retry.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )
        cleanups.append(
            lambda: call_safe(
                aws_client_no_retry.cloudformation.delete_change_set,
                kwargs=dict(ChangeSetName=change_set_id),
            )
        )

        describe_change_set_with_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=True
            )
        )
        _normalise_describe_change_set_output(describe_change_set_with_prop_values)
        snapshot.match("describe-change-set-1-prop-values", describe_change_set_with_prop_values)

        describe_change_set_without_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=False
            )
        )
        _normalise_describe_change_set_output(describe_change_set_without_prop_values)
        snapshot.match("describe-change-set-1", describe_change_set_without_prop_values)

        execute_results = aws_client_no_retry.cloudformation.execute_change_set(
            ChangeSetName=change_set_id
        )
        snapshot.match("execute-change-set-1", execute_results)
        aws_client_no_retry.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack_id
        )

        # ensure stack deletion
        cleanups.append(
            lambda: call_safe(
                aws_client_no_retry.cloudformation.delete_stack, kwargs=dict(StackName=stack_id)
            )
        )

        describe = aws_client_no_retry.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][
            0
        ]
        snapshot.match("post-create-1-describe", describe)

        # update stack
        change_set_details = aws_client_no_retry.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=t2,
            ChangeSetType="UPDATE",
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for (k, v) in p2.items()],
        )
        snapshot.match("create-change-set-2", change_set_details)
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client_no_retry.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )

        describe_change_set_with_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=True
            )
        )
        _normalise_describe_change_set_output(describe_change_set_with_prop_values)
        snapshot.match("describe-change-set-2-prop-values", describe_change_set_with_prop_values)

        describe_change_set_without_prop_values = (
            aws_client_no_retry.cloudformation.describe_change_set(
                ChangeSetName=change_set_id, IncludePropertyValues=False
            )
        )
        _normalise_describe_change_set_output(describe_change_set_without_prop_values)
        snapshot.match("describe-change-set-2", describe_change_set_without_prop_values)

        execute_results = aws_client_no_retry.cloudformation.execute_change_set(
            ChangeSetName=change_set_id
        )
        snapshot.match("execute-change-set-2", execute_results)
        aws_client_no_retry.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack_id
        )

        describe = aws_client_no_retry.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][
            0
        ]
        snapshot.match("post-create-2-describe", describe)

        events = capture_per_resource_events(stack_name)
        snapshot.match("per-resource-events", events)

        # delete stack
        aws_client_no_retry.cloudformation.delete_stack(StackName=stack_id)
        aws_client_no_retry.cloudformation.get_waiter("stack_delete_complete").wait(
            StackName=stack_id
        )
        describe = aws_client_no_retry.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][
            0
        ]
        snapshot.match("delete-describe", describe)

    yield inner
