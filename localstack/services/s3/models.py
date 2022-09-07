from typing import Dict, List

from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)


class S3Store(BaseStore):
    # store bucket names
    # They must be unique across all AWS accounts in all the AWS Regions within a partition
    bucket_names: Dict[str, str] = CrossRegionAttribute(default=dict)

    # maps bucket name to bucket's list of notification configurations
    # TODO: check type
    bucket_notification_configs: List[Dict] = LocalAttribute(default=list)

    # maps bucket name to bucket's CORS settings
    bucket_cors: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps bucket name to bucket's lifecycle settings
    bucket_lifecycle: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps bucket name to bucket's replication settings
    bucket_replication: Dict[str, List[Dict]] = LocalAttribute(default=dict)


s3_stores = AccountRegionBundle("s3", S3Store)
