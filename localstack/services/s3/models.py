from typing import Dict, Set  # , List

from localstack.aws.api.s3 import (
    BucketName,
    CORSConfiguration,
    LifecycleConfiguration,
    NotificationConfiguration,
    ReplicationConfiguration,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class S3Store(BaseStore):
    # store bucket names
    # They must be unique across all AWS accounts in all the AWS Regions within a partition
    # this might not be needed, Moto handles it
    bucket_names: Set[BucketName] = CrossRegionAttribute(default=set)

    # maps bucket name to bucket's list of notification configurations
    bucket_notification_configs: Dict[BucketName, NotificationConfiguration] = LocalAttribute(
        default=dict
    )

    # maps bucket name to bucket's CORS settings
    bucket_cors: Dict[BucketName, CORSConfiguration] = LocalAttribute(default=dict)

    # maps bucket name to bucket's lifecycle settings
    bucket_lifecycle: Dict[BucketName, LifecycleConfiguration] = LocalAttribute(default=dict)

    # maps bucket name to bucket's replication settings
    bucket_replication: Dict[BucketName, ReplicationConfiguration] = LocalAttribute(default=dict)

    # bucket_objects? store full config in one key?


s3_stores = AccountRegionBundle("s3", S3Store)
