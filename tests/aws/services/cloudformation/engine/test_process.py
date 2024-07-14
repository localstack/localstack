"""
For testing the core template parsing and execution process by injecting artificial failures into templates, and capturing what issue causes the actual stack failure.

Four possible error locations:
- create change set (sync)
- create change set (async)
- Execute change set (sync)*
- Execute change set (async)

*: no observed failures so no test
"""

import textwrap

import pytest
import yaml

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

pytestmark = [
    markers.aws.validated,
]


class TestCreateChangesetSync:
    def test_invalid_yaml(self, aws_client: ServiceLevelClientFactory, snapshot):
        template = textwrap.dedent("""
        Resources:
        bad-indent
        """)

        with pytest.raises(Exception):
            yaml.safe_load(template)

        with pytest.raises(Exception) as exc:
            aws_client.cloudformation.create_change_set(
                StackName=f"stack-{short_uid()}",
                ChangeSetName=f"cs-{short_uid()}",
                ChangeSetType="CREATE",
                TemplateBody=template,
            )

        snapshot.match("error", str(exc.value))


class TestCreateChangesetAync:
    pass


class TestExecuteChangesetAsync:
    pass
