"""
For testing the core template parsing and execution process by injecting artificial failures into templates, and capturing what issue causes the actual stack failure.

Four possible error locations:
- create change set (sync)
- create change set (async)
- Execute change set (sync)*
- Execute change set (async)

*: no observed failures so no test
"""

import json
import textwrap
from typing import Callable, TypeAlias

import pytest
import yaml
from botocore.exceptions import ClientError, WaiterError
from localstack_snapshot.snapshots.prototype import SnapshotSession

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = [
    markers.aws.validated,
]

Template: TypeAlias = str | dict


@pytest.fixture
def stack_name() -> str:
    return f"stack-{short_uid()}"


@pytest.fixture
def change_set_name() -> str:
    return f"cs-{short_uid()}"


@pytest.fixture
def run_sample(
    aws_client: ServiceLevelClientFactory,
    snapshot: SnapshotSession,
    stack_name: str,
    change_set_name: str,
):
    client = aws_client.cloudformation

    def inner(template: Template):
        def deploy():
            if isinstance(template, dict):
                template_str = json.dumps(template)
            elif isinstance(template, str):
                template_str = template
            else:
                raise ValueError()

            client.create_change_set(
                StackName=stack_name,
                ChangeSetName=change_set_name,
                ChangeSetType="CREATE",
                TemplateBody=template_str,
            )
            client.get_waiter("change_set_create_complete").wait(
                StackName=stack_name,
                ChangeSetName=change_set_name,
            )

            client.execute_change_set(
                StackName=stack_name,
                ChangeSetName=change_set_name,
            )
            client.get_waiter("stack_exists").wait(
                StackName=stack_name,
            )

        try:
            deploy()
        except ClientError as exc:
            # snapshot.match("error", exc.response.get("Error", {}))
            snapshot.match("error", str(exc))
        except WaiterError as exc:
            # snapshot.match("error", exc.response.get("Error", {}))
            snapshot.match("error", str(exc))
        else:
            pytest.fail("no error detected")

    yield inner

    try:
        client.delete_stack(StackName=stack_name)
    except:  # noqa: E722
        pass


class TestCreateChangesetSync:
    def test_invalid_yaml(
        self,
        run_sample: Callable[..., None],
    ):
        template = textwrap.dedent("""
        Resources:
        bad-indent
        """)

        with pytest.raises(Exception):
            yaml.safe_load(template)

        run_sample(template)

    def test_missing_required_top_level_key(self, run_sample: Callable[..., None]):
        template = {}
        run_sample(template)


class TestCreateChangesetAync:
    pass


class TestExecuteChangesetAsync:
    pass
