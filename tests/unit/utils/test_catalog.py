import pytest

from localstack.utils.catalog.catalog import AwsCatalogPlugin
from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
    CloudFormationResourcesSupportAtRuntime,
)
from localstack.utils.catalog.loader import AwsRemoteCatalog, RemoteCatalogLoader


class FakeCatalogLoader(RemoteCatalogLoader):
    def __init__(self, catalog: AwsRemoteCatalog):
        self.catalog = catalog

    def get_remote_catalog(self) -> AwsRemoteCatalog:
        return self.catalog


CATALOG = AwsRemoteCatalog(
    schema_version="1.0",
    localstack={},
    services={
        "athena": {
            "pro": {
                "provider": "athena:pro",
                "operations": ["StartQueryExecution", "GetQueryExecution"],
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


@pytest.fixture(scope="class", autouse=True)
def aws_catalog():
    return AwsCatalogPlugin(FakeCatalogLoader(CATALOG))


class TestAwsCatalog:
    @pytest.mark.parametrize(
        "service_name,expected_status",
        [
            ("s3", AwsServicesSupportInLatest.SUPPORTED),
            ("athena", AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE),
            ("nonexistent", AwsServicesSupportInLatest.NOT_SUPPORTED),
        ],
    )
    def test_get_service_status(self, aws_catalog, service_name, expected_status):
        result = aws_catalog.get_aws_service_status(service_name)
        assert result == expected_status

    @pytest.mark.parametrize(
        "service_name,operation_name,expected_status",
        [
            ("kms", "ListKeys", AwsServiceOperationsSupportInLatest.SUPPORTED),
            (
                "s3",
                "SelectObjectContent",
                AwsServiceOperationsSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE,
            ),
            ("s3", "UnsupportedOp", AwsServiceOperationsSupportInLatest.NOT_SUPPORTED),
        ],
    )
    def test_get_service_status_with_operation(
        self, aws_catalog, service_name, operation_name, expected_status
    ):
        result = aws_catalog.get_aws_service_status(service_name, operation_name)
        assert result == expected_status

    def test_get_service_status_with_only_one_emulator_type(self, aws_catalog):
        result = aws_catalog.get_aws_service_status("athena")
        assert result == AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE

    def test_get_service_status_with_empty_operation(self, aws_catalog):
        assert (
            aws_catalog.get_aws_service_status("s3", None) == AwsServicesSupportInLatest.SUPPORTED
        )
        assert (
            aws_catalog.get_aws_service_status("s3", "")
            == AwsServiceOperationsSupportInLatest.SUPPORTED
        )

    @pytest.mark.parametrize(
        "resource_name,expected_status",
        [
            ("AWS::S3::Bucket", CloudFormationResourcesSupportAtRuntime.AVAILABLE),
            ("AWS::S3::NonExistent", AwsServicesSupportInLatest.SUPPORTED),
            (
                "AWS::Athena::CapacitiesReservation",
                AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE,
            ),
            ("AWS::NonExistentService::NonExistent", AwsServicesSupportInLatest.NOT_SUPPORTED),
        ],
    )
    def test_get_cfn_resource_status(self, aws_catalog, resource_name, expected_status):
        result = aws_catalog.get_cloudformation_resource_status(resource_name)
        assert result == expected_status
