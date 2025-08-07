from collections import defaultdict

from localstack.aws.api.kinesis import ConsumerDescription, MetricsName, StreamName
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class KinesisStore(BaseStore):
    # list of stream consumer details
    stream_consumers: list[ConsumerDescription] = LocalAttribute(default=list)

    # maps stream name to list of enhanced monitoring metrics
    enhanced_metrics: dict[StreamName, set[MetricsName]] = LocalAttribute(
        default=lambda: defaultdict(set)
    )


kinesis_stores = AccountRegionBundle("kinesis", KinesisStore)
