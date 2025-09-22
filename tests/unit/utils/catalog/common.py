from localstack.utils.catalog.common import AwsRemoteCatalog, LocalStackMetadata

CATALOG = AwsRemoteCatalog(
    schema_version="v1",
    localstack=LocalStackMetadata(version="4.7"),
    services={
        "athena": {
            "pro": {
                "provider": "athena:pro",
                "operations": ["StartQueryExecution", "GetQueryExecution"],
                "plans": ["ultimate", "enterprise"],
            }
        },
        "s3": {
            "community": {
                "provider": "s3:default",
                "operations": ["CreateBucket"],
                "plans": ["free", "base", "ultimate", "enterprise"],
            },
            "pro": {
                "provider": "s3:pro",
                "operations": ["SelectObjectContent"],
                "plans": ["base", "ultimate", "enterprise"],
            },
        },
        "kms": {
            "community": {
                "provider": "kms:default",
                "operations": ["ListKeys"],
                "plans": ["free", "base", "ultimate", "enterprise"],
            }
        },
    },
    cloudformation_resources={
        "community": {"AWS::S3::Bucket": {"methods": ["Create", "Delete"]}},
        "pro": {"AWS::Athena::CapacitiesReservation": {"methods": ["Create", "Update", "Delete"]}},
    },
)
