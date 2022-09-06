from typing import Dict

from localstack.aws.api.firehose import DeliveryStreamDescription
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.kinesis.kinesis_connector import KinesisProcessorThread
from localstack.utils.tagging import TaggingService


class FirehoseStore(BaseStore):
    # maps delivery stream names to DeliveryStreamDescription
    delivery_streams: Dict[str, DeliveryStreamDescription] = LocalAttribute(default=dict)

    kinesis_listeners: Dict[str, KinesisProcessorThread] = LocalAttribute(default=dict)

    # static tagging service instance
    TAGS = CrossRegionAttribute(default=TaggingService)


firehose_stores = AccountRegionBundle("firehose", FirehoseStore)
