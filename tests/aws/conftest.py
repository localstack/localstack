from _pytest.config import Config

from localstack import config as localstack_config
from localstack import constants
from tests.aws.services.es.test_es import install_async as es_install_async
from tests.aws.services.opensearch.test_opensearch import install_async as opensearch_install_async
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
            test_init_functions.add(opensearch_install_async)
        if any(opensearch_test in parent_name for opensearch_test in ["test_es", "firehose"]):
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
