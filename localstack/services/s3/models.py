from typing import Dict

from localstack.aws.api.s3 import (
    BucketLifecycleConfiguration,
    BucketName,
    CORSConfiguration,
    NotificationConfiguration,
    ReplicationConfiguration,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class S3Store(BaseStore):
    # maps bucket name to bucket's list of notification configurations
    bucket_notification_configs: Dict[BucketName, NotificationConfiguration] = LocalAttribute(
        default=dict
    )

    # maps bucket name to bucket's CORS settings
    bucket_cors: Dict[BucketName, CORSConfiguration] = LocalAttribute(default=dict)

    # maps bucket name to bucket's replication settings
    bucket_replication: Dict[BucketName, ReplicationConfiguration] = LocalAttribute(default=dict)

    # maps bucket name to bucket's lifecycle configuration
    # TODO: need to check "globality" of parameters / redirect
    bucket_lifecycle_configuration: Dict[BucketName, BucketLifecycleConfiguration] = LocalAttribute(
        default=dict
    )


s3_stores = AccountRegionBundle("s3", S3Store)
