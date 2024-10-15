import logging
import random
import string
from typing import Union

from moto.utilities import id_generator as moto_id_generator
from moto.utilities.id_generator import IdSourceContext, MotoIdManager, moto_id
from moto.utilities.id_generator import ResourceIdentifier as MotoResourceIdentifier

from localstack.utils.strings import long_uid, short_uid

LOG = logging.getLogger(__name__)

ExistingIds = list[str] | None
Tags = dict[str, str] | None


class LocalstackIdManager(MotoIdManager):
    def set_custom_id_by_unique_identifier(self, unique_identifier: str, custom_id: str):
        with self._lock:
            self._custom_ids[unique_identifier] = custom_id

    def find_id_from_sources(self, id_source_context: IdSourceContext) -> Union[str, None]:
        existing_ids = id_source_context.get("existing_ids") or []
        resource_identifier = id_source_context["resource_identifier"]
        validator = getattr(resource_identifier, "validator", None)

        for id_source in self._id_sources:
            if found_id := id_source(id_source_context):
                if found_id in existing_ids:
                    LOG.debug(
                        "Found id %s for resource %s, but a resource already exists with this id.",
                        found_id,
                        resource_identifier,
                    )
                elif validator and not validator(found_id):
                    LOG.debug(
                        "Found id %s for resource %s, but the id failed validation.",
                        found_id,
                        resource_identifier,
                    )
                else:
                    return found_id

        return None


localstack_id_manager = LocalstackIdManager()
moto_id_generator.moto_id_manager = localstack_id_manager
localstack_id = moto_id

ResourceIdentifier = MotoResourceIdentifier


@localstack_id
def generate_uid(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
    length=36,
) -> str:
    return long_uid()[:length]


@localstack_id
def generate_short_uid(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
) -> str:
    return short_uid()


@localstack_id
def generate_str_id(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
    length=8,
) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))
