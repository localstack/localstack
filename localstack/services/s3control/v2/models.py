from localstack.aws.api.s3control import PublicAccessBlockConfiguration
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
)


class S3ControlStore(BaseStore):
    # buckets: dict[BucketName, S3Bucket] = CrossRegionAttribute(default=dict)
    public_access_block: PublicAccessBlockConfiguration = CrossRegionAttribute(default=dict)
    # access_point_alias: dict[Alias, BucketName] = CrossRegionAttribute(default=dict)
    # global_bucket_map: dict[BucketName, AccountId] = CrossAccountAttribute(default=dict)


s3control_stores = AccountRegionBundle[S3ControlStore]("s3control", S3ControlStore)
