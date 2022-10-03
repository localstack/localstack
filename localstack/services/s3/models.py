from typing import Dict

from moto.s3 import s3_backends as moto_s3_backends
from moto.s3.models import S3Backend as MotoS3Backend

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    BucketLifecycleConfiguration,
    BucketName,
    CORSConfiguration,
    NotificationConfiguration,
    ReplicationConfiguration,
    WebsiteConfiguration,
)
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


def get_moto_s3_backend(context: RequestContext = None) -> MotoS3Backend:
    account_id = context.account_id if context else DEFAULT_AWS_ACCOUNT_ID
    return moto_s3_backends[account_id]["global"]


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

    bucket_website_configuration: Dict[BucketName, WebsiteConfiguration] = LocalAttribute(
        default=dict
    )


s3_stores = AccountRegionBundle("s3", S3Store)
