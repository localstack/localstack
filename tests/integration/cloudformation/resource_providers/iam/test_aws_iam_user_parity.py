# flake8: noqa
import os

import pytest

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest.fixtures import StackDeployError

pytestmark = [pytest.mark.skip(reason="in progress")]


class TestParity:
    def test_create_with_full_properties(self):
        # TODO
        ...

    def test_update_policy_json(self):
        # TODO
        ...


class TestSamples:
    ...
