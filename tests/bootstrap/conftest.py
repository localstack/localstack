import os
from typing import Optional

import pytest

from localstack import constants
from localstack.testing.scenario.provisioning import InfraProvisioner

pytest_plugins = [
    "localstack.testing.pytest.bootstrap",
]


@pytest.fixture(scope="session")
def cdk_template_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "cdk_templates"))


# Duplicated from tests/aws/conftest.py so we can use CDK with bootstrap tests
@pytest.fixture(scope="session")
def infrastructure_setup(cdk_template_path, aws_client_factory):
    def _infrastructure_setup(
        namespace: str, force_synth: Optional[bool] = False, port: int = constants.DEFAULT_PORT_EDGE
    ) -> InfraProvisioner:
        """
        :param namespace: repo-unique identifier for this CDK app.
            A directory with this name will be created at `tests/aws/cdk_templates/<namespace>/`
        :param force_synth: set to True to always re-synth the CDK app
        :return: an instantiated CDK InfraProvisioner which can be used to deploy a CDK app
        """
        return InfraProvisioner(
            base_path=cdk_template_path,
            aws_client=aws_client_factory(endpoint_url=f"http://localhost:{port}"),
            namespace=namespace,
            force_synth=force_synth,
            persist_output=True,
        )

    return _infrastructure_setup
