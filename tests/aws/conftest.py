import os
from typing import Optional

import pytest
from _pytest.config import Config
from localstack_snapshot.snapshots import SnapshotSession
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack import config as localstack_config
from localstack import constants
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.testing.snapshots.transformer_utility import (
    SNAPSHOT_BASIC_TRANSFORMER,
    SNAPSHOT_BASIC_TRANSFORMER_NEW,
    TransformerUtility,
)
from tests.aws.test_terraform import TestTerraform


def pytest_configure(config: Config):
    # FIXME: note that this should be the same as in tests/integration/conftest.py since both are currently
    #  run in the same CI test step, but only one localstack instance is started for both.
    config.option.start_localstack = True
    localstack_config.FORCE_SHUTDOWN = False
    localstack_config.GATEWAY_LISTEN = localstack_config.UniqueHostAndPortList(
        [localstack_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)]
    )


def pytest_runtestloop(session):
    # second pytest lifecycle hook (before test runner starts)
    test_init_functions = set()

    # collect test classes
    test_classes = set()
    for item in session.items:
        if item.parent and item.parent.cls:
            test_classes.add(item.parent.cls)
        # OpenSearch/Elasticsearch are pytests, not unit test classes, so we check based on the item parent's name.
        # Any pytests that rely on opensearch/elasticsearch must be special-cased by adding them to the list below
        parent_name = str(item.parent).lower()
        if any(opensearch_test in parent_name for opensearch_test in ["opensearch", "firehose"]):
            from tests.aws.services.opensearch.test_opensearch import (
                install_async as opensearch_install_async,
            )

            test_init_functions.add(opensearch_install_async)
        if any(opensearch_test in parent_name for opensearch_test in ["test_es", "firehose"]):
            from tests.aws.services.es.test_es import install_async as es_install_async

            test_init_functions.add(es_install_async)

    # add init functions for certain tests that download/install things
    for test_class in test_classes:
        # set flag that terraform will be used
        if TestTerraform is test_class:
            test_init_functions.add(TestTerraform.init_async)
            continue

    if not session.items:
        return

    if session.config.option.collectonly:
        return

    for fn in test_init_functions:
        fn()


# Note: Don't move this into testing lib
@pytest.fixture(scope="session")
def cdk_template_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "cdk_templates"))


# Note: Don't move this into testing lib
@pytest.fixture(scope="session")
def infrastructure_setup(cdk_template_path, aws_client):
    def _infrastructure_setup(
        namespace: str, force_synth: Optional[bool] = False
    ) -> InfraProvisioner:
        """
        :param namespace: repo-unique identifier for this CDK app.
            A directory with this name will be created at `tests/aws/cdk_templates/<namespace>/`
        :param force_synth: set to True to always re-synth the CDK app
        :return: an instantiated CDK InfraProvisioner which can be used to deploy a CDK app
        """
        return InfraProvisioner(
            base_path=cdk_template_path,
            aws_client=aws_client,
            namespace=namespace,
            force_synth=force_synth,
            persist_output=True,
        )

    return _infrastructure_setup


@pytest.fixture(scope="function")
def snapshot(request, _snapshot_session: SnapshotSession, aws_client):
    account_id = aws_client.sts.get_caller_identity()["Account"]
    region = aws_client.sts.meta.region_name

    # Overwrite utility with our own => Will be refactored in the future
    _snapshot_session.transform = TransformerUtility

    _snapshot_session.add_transformer(RegexTransformer(account_id, "1" * 12), priority=2)
    _snapshot_session.add_transformer(RegexTransformer(region, "<region>"), priority=2)

    # TODO: temporary to migrate to new default transformers.
    #   remove this after all exemptions are gone
    exemptions = [
        "tests/aws/services/acm",
        "tests/aws/services/apigateway",
        "tests/aws/services/cloudwatch",
        "tests/aws/services/cloudformation",
        "tests/aws/services/dynamodb",
        "tests/aws/services/events",
        "tests/aws/services/iam",
        "tests/aws/services/kinesis",
        "tests/aws/services/kms",
        "tests/aws/services/lambda_",
        "tests/aws/services/logs",
        "tests/aws/services/route53",
        "tests/aws/services/route53resolver",
        "tests/aws/services/s3",
        "tests/aws/services/secretsmanager",
        "tests/aws/services/ses",
        "tests/aws/services/sns",
        "tests/aws/services/stepfunctions",
        "tests/aws/services/sqs",
        "tests/aws/services/transcribe",
        "tests/aws/scenario/bookstore",
        "tests/aws/scenario/note_taking",
        "tests/aws/scenario/lambda_destination",
        "tests/aws/scenario/loan_broker",
    ]
    if any([e in request.fspath.dirname for e in exemptions]):
        _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER, priority=2)
    else:
        _snapshot_session.add_transformer(SNAPSHOT_BASIC_TRANSFORMER_NEW, priority=2)

    return _snapshot_session
