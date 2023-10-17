from moto.s3 import s3_backends as moto_s3_backends
from moto.s3.models import S3Backend as MotoS3Backend

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    AnalyticsConfiguration,
    AnalyticsId,
    BucketLifecycleConfiguration,
    BucketName,
    CORSConfiguration,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InventoryConfiguration,
    InventoryId,
    NotificationConfiguration,
    ReplicationConfiguration,
    WebsiteConfiguration,
)
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


def get_moto_s3_backend(context: RequestContext = None) -> MotoS3Backend:
    account_id = context.account_id if context else DEFAULT_AWS_ACCOUNT_ID
    return moto_s3_backends[account_id]["global"]


class S3Store(BaseStore):
    # maps bucket name to bucket's list of notification configurations
    bucket_notification_configs: dict[BucketName, NotificationConfiguration] = CrossRegionAttribute(
        default=dict
    )

    # maps bucket name to bucket's CORS settings, used as index
    bucket_cors: dict[BucketName, CORSConfiguration] = CrossRegionAttribute(default=dict)

    # maps bucket name to bucket's replication settings
    bucket_replication: dict[BucketName, ReplicationConfiguration] = CrossRegionAttribute(
        default=dict
    )

    # maps bucket name to bucket's lifecycle configuration
    bucket_lifecycle_configuration: dict[
        BucketName, BucketLifecycleConfiguration
    ] = CrossRegionAttribute(default=dict)

    bucket_versioning_status: dict[BucketName, bool] = CrossRegionAttribute(default=dict)

    bucket_website_configuration: dict[BucketName, WebsiteConfiguration] = CrossRegionAttribute(
        default=dict
    )

    bucket_analytics_configuration: dict[
        BucketName, dict[AnalyticsId, AnalyticsConfiguration]
    ] = CrossRegionAttribute(default=dict)

    bucket_intelligent_tiering_configuration: dict[
        BucketName, dict[IntelligentTieringId, IntelligentTieringConfiguration]
    ] = CrossRegionAttribute(default=dict)

    bucket_inventory_configurations: dict[
        BucketName, dict[InventoryId, InventoryConfiguration]
    ] = CrossRegionAttribute(default=dict)


class BucketCorsIndex:
    def __init__(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @property
    def cors(self) -> dict[str, CORSConfiguration]:
        if self._cors_index_cache is None:
            self._cors_index_cache = self._build_cors_index()
        return self._cors_index_cache

    @property
    def buckets(self) -> set[str]:
        if self._bucket_index_cache is None:
            self._bucket_index_cache = self._build_bucket_index()
        return self._bucket_index_cache

    def invalidate(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @staticmethod
    def _build_cors_index() -> dict[BucketName, CORSConfiguration]:
        result = {}
        for account_id, regions in s3_stores.items():
            result.update(regions[AWS_REGION_US_EAST_1].bucket_cors)
        return result

    @staticmethod
    def _build_bucket_index() -> set[BucketName]:
        result = set()
        for account_id, regions in list(moto_s3_backends.items()):
            result.update(regions["global"].buckets.keys())
        return result


s3_stores = AccountRegionBundle[S3Store]("s3", S3Store)
