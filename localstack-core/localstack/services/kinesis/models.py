from collections import defaultdict
from typing import Dict, List, Set

from localstack.aws.api.kinesis import ConsumerDescription, MetricsName, StreamName
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class KinesisStore(BaseStore):
    # list of stream consumer details
    stream_consumers: List[ConsumerDescription] = LocalAttribute(default=list)

    # maps stream name to list of enhanced monitoring metrics
    enhanced_metrics: Dict[StreamName, Set[MetricsName]] = LocalAttribute(
        default=lambda: defaultdict(set)
    )


kinesis_stores = AccountRegionBundle("kinesis", KinesisStore)
