from typing import Dict

import moto.s3.models as moto_s3_models
from moto.s3 import s3_backends as moto_s3_backends

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    BucketLifecycleConfiguration,
    BucketName,
    CORSConfiguration,
    NotificationConfiguration,
    ReplicationConfiguration,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


def get_moto_s3_backend(context: RequestContext) -> moto_s3_models.S3Backend:
    return moto_s3_backends[context.account_id]["global"]


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

    bucket_versioning_status: Dict[BucketName, bool] = LocalAttribute(default=dict)


s3_stores = AccountRegionBundle("s3", S3Store)
