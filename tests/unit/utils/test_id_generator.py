import pytest

from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.utils.id_generator import (
    generate_short_uid,
    generate_str_id,
    generate_uid,
    set_custom_id,
    unset_custom_id,
)
from localstack.utils.strings import long_uid, short_uid

TEST_SERVICE = "test-service"
TEST_NAME = "test-name"
TEST_RESOURCE = "test-resource"


@pytest.fixture
def configure_custom_id(unset_configured_custom_id):
    def _configure_custom_id(custom_id: str):
        set_custom_id(
            account_id=TEST_AWS_ACCOUNT_ID,
            region=TEST_AWS_REGION_NAME,
            service=TEST_SERVICE,
            resource=TEST_RESOURCE,
            name=TEST_NAME,
            custom_id=custom_id,
        )

    yield _configure_custom_id

    # we reset the ids after each test
    unset_configured_custom_id()


@pytest.fixture
def unset_configured_custom_id():
    def _unset():
        unset_custom_id(
            account_id=TEST_AWS_ACCOUNT_ID,
            region=TEST_AWS_REGION_NAME,
            service=TEST_SERVICE,
            resource=TEST_RESOURCE,
            name=TEST_NAME,
        )

    return _unset


def test_generate_short_id(configure_custom_id, unset_configured_custom_id):
    custom_id = short_uid()
    configure_custom_id(custom_id)

    generated = generate_short_uid(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME
    )
    assert generated == custom_id

    unset_configured_custom_id()
    generated = generate_short_uid(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME
    )
    assert generated != custom_id


def test_generate_uid(configure_custom_id, unset_configured_custom_id):
    custom_id = long_uid()
    configure_custom_id(custom_id)

    generated = generate_uid(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME
    )
    assert generated == custom_id

    unset_configured_custom_id()

    # test configured length
    generated = generate_uid(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME, length=9
    )
    assert generated != custom_id
    assert len(generated) == 9


def test_generate_str_id(configure_custom_id, unset_configured_custom_id):
    custom_id = "RandomString"
    configure_custom_id(custom_id)

    generated = generate_str_id(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME
    )
    assert generated == custom_id

    unset_configured_custom_id()

    # test configured length
    generated = generate_str_id(
        TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_SERVICE, TEST_RESOURCE, TEST_NAME, length=9
    )
    assert generated != custom_id
    assert len(generated) == 9
