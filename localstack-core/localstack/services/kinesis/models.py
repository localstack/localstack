from collections import defaultdict
from typing import Dict, List, Set

from localstack.aws.api.kinesis import (
    ConsumerDescription,
    MetricsName,
    Policy,
    ResourceARN,
    StreamName,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    LocalAttribute,
)


class KinesisStore(BaseStore):
    # list of stream consumer details
    stream_consumers: List[ConsumerDescription] = LocalAttribute(default=list)

    # maps stream name to list of enhanced monitoring metrics
    enhanced_metrics: Dict[StreamName, Set[MetricsName]] = LocalAttribute(
        default=lambda: defaultdict(set)
    )

    resource_policies: Dict[ResourceARN, Policy] = CrossAccountAttribute(default=dict)


kinesis_stores = AccountRegionBundle("kinesis", KinesisStore)
