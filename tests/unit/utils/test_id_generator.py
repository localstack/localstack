import pytest

from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.services.cloudformation.engine.entities import StackIdentifier
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.utils.id_generator import (
    ResourceIdentifier,
    generate_short_uid,
    generate_str_id,
    generate_uid,
    localstack_id_manager,
)
from localstack.utils.strings import long_uid, short_uid

TEST_NAME = "test-name"


@pytest.fixture
def default_resource_identifier():
    return StackIdentifier(TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, TEST_NAME)


@pytest.fixture
def configure_custom_id(unset_configured_custom_id, default_resource_identifier):
    set_identifier = [default_resource_identifier]

    def _configure_custom_id(custom_id: str, resource_identifier=None):
        localstack_id_manager.set_custom_id(
            resource_identifier or default_resource_identifier, custom_id=custom_id
        )
        if resource_identifier:
            set_identifier.append(resource_identifier)

    yield _configure_custom_id

    # we reset the ids after each test
    for identifier in set_identifier:
        unset_configured_custom_id(identifier)


@pytest.fixture
def unset_configured_custom_id(default_resource_identifier):
    def _unset(resource_identifier: ResourceIdentifier = None):
        localstack_id_manager.unset_custom_id(resource_identifier or default_resource_identifier)

    return _unset


def test_generate_short_id(
    configure_custom_id, unset_configured_custom_id, default_resource_identifier
):
    custom_id = short_uid()
    configure_custom_id(custom_id)

    generated = generate_short_uid(default_resource_identifier)
    assert generated == custom_id

    unset_configured_custom_id()
    generated = generate_short_uid(default_resource_identifier)
    assert generated != custom_id


def test_generate_uid(configure_custom_id, unset_configured_custom_id, default_resource_identifier):
    custom_id = long_uid()
    configure_custom_id(custom_id)

    generated = generate_uid(default_resource_identifier)
    assert generated == custom_id

    unset_configured_custom_id()

    # test configured length
    generated = generate_uid(default_resource_identifier, length=9)
    assert generated != custom_id
    assert len(generated) == 9


def test_generate_str_id(
    configure_custom_id, unset_configured_custom_id, default_resource_identifier
):
    custom_id = "RandomString"
    configure_custom_id(custom_id)

    generated = generate_str_id(default_resource_identifier)
    assert generated == custom_id

    unset_configured_custom_id()

    # test configured length
    generated = generate_str_id(default_resource_identifier, length=9)
    assert generated != custom_id
    assert len(generated) == 9


def test_generate_with_custom_id_tag(
    configure_custom_id, unset_configured_custom_id, default_resource_identifier
):
    custom_id = "set_id"
    tag_custom_id = "id_from_tag"
    configure_custom_id(custom_id)

    # If the tags are passed, they should have priority
    generated = generate_str_id(
        default_resource_identifier, tags={TAG_KEY_CUSTOM_ID: tag_custom_id}
    )
    assert generated == tag_custom_id
    generated = generate_str_id(default_resource_identifier)
    assert generated == custom_id


def test_generate_from_unique_identifier_string(
    unset_configured_custom_id, default_resource_identifier, cleanups
):
    custom_id = "set_id"
    unique_identifier_string = default_resource_identifier.unique_identifier

    localstack_id_manager.set_custom_id_by_unique_identifier(unique_identifier_string, custom_id)
    cleanups.append(lambda: unset_configured_custom_id(default_resource_identifier))

    generated = generate_str_id(default_resource_identifier)
    assert generated == custom_id
