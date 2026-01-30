import os

from localstack import config
from localstack.config import is_env_true
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID

# Credentials used in the test suite
# These can be overridden if the tests are being run against AWS
TEST_AWS_ACCOUNT_ID = os.getenv("TEST_AWS_ACCOUNT_ID") or DEFAULT_AWS_ACCOUNT_ID
# If a structured access key ID is used, it must correspond to the account ID
TEST_AWS_ACCESS_KEY_ID = os.getenv("TEST_AWS_ACCESS_KEY_ID") or "test"
TEST_AWS_SECRET_ACCESS_KEY = os.getenv("TEST_AWS_SECRET_ACCESS_KEY") or "test"
TEST_AWS_REGION_NAME = os.getenv("TEST_AWS_REGION_NAME") or "us-east-1"
TEST_AWS_ENDPOINT_URL = os.getenv("TEST_AWS_ENDPOINT_URL") or config.internal_service_url()

# Secondary test AWS profile - only used for testing against AWS
SECONDARY_TEST_AWS_PROFILE = os.getenv("SECONDARY_TEST_AWS_PROFILE")
# Additional credentials used in the test suite (when running cross-account tests)
SECONDARY_TEST_AWS_ACCOUNT_ID = os.getenv("SECONDARY_TEST_AWS_ACCOUNT_ID") or "000000000002"
SECONDARY_TEST_AWS_ACCESS_KEY_ID = os.getenv("SECONDARY_TEST_AWS_ACCESS_KEY_ID") or "000000000002"
SECONDARY_TEST_AWS_SECRET_ACCESS_KEY = os.getenv("SECONDARY_TEST_AWS_SECRET_ACCESS_KEY") or "test2"
SECONDARY_TEST_AWS_SESSION_TOKEN = os.getenv("SECONDARY_TEST_AWS_SESSION_TOKEN")
SECONDARY_TEST_AWS_REGION_NAME = os.getenv("SECONDARY_TEST_AWS_REGION_NAME") or "ap-southeast-1"

TEST_SKIP_LOCALSTACK_START = is_env_true("TEST_SKIP_LOCALSTACK_START")
TEST_FORCE_LOCALSTACK_START = is_env_true("TEST_FORCE_LOCALSTACK_START")
