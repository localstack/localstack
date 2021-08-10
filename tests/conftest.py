import os

os.environ["LOCALSTACK_INTERNAL_TEST_RUN"] = "1"

pytest_plugins = [
    "tests.integration.fixtures",
]
