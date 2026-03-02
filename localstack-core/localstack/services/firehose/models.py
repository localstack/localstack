from localstack.aws.api.firehose import DeliveryStreamDescription
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    LocalAttribute,
)
from localstack.utils.tagging import Tags


class FirehoseStore(BaseStore):
    # maps delivery stream names to DeliveryStreamDescription
    delivery_streams: dict[str, DeliveryStreamDescription] = LocalAttribute(default=dict)

    # resource tags
    tags: Tags = LocalAttribute(default=Tags)


firehose_stores = AccountRegionBundle("firehose", FirehoseStore)
