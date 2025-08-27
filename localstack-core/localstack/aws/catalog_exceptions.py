from localstack.aws.api import CommonServiceException
from localstack.utils.catalog.common import (
    AwsServiceOperationsSupportInLatest,
    AwsServicesSupportInLatest,
)

_DOCS_COVERAGE_URL = "https://docs.localstack.cloud/references/coverage"


class AwsServiceAvailabilityException(CommonServiceException):
    def __init__(self, message: str, error_code: int):
        super().__init__(code="InternalFailure", message=message, status_code=501)
        self.error_code = error_code


class ServiceNotSupportedException(AwsServiceAvailabilityException):
    def __init__(self, service_name: str):
        super().__init__(
            f"Sorry, the {service_name} service is not currently supported by LocalStack.",
            error_code=3,
        )


class LatestVersionRequiredException(AwsServiceAvailabilityException):
    def __init__(self, service_name: str, operation_name: str | None = None):
        if operation_name is None:
            message = f"Sorry, the {service_name} service is not supported by this version of LocalStack, but is available if you upgrade to the latest stable version."
            error_code = 2
        else:
            message = f"Sorry, the {operation_name} operation on the {service_name} service is not supported by this version of LocalStack, but is available if you upgrade to the latest stable version."
            error_code = 6
        super().__init__(message, error_code)


class LicenseUpgradeRequiredException(AwsServiceAvailabilityException):
    def __init__(self, service_name: str, operation_name: str | None = None):
        if operation_name is None:
            message = f"Sorry, the {service_name} service is not included within your LocalStack license, but is available in an upgraded license. Please refer to {_DOCS_COVERAGE_URL} for more details."
            error_code = 1
        else:
            message = f"Sorry, the {operation_name} operation on the {service_name} service is not supported with your LocalStack license. Please refer to {_DOCS_COVERAGE_URL} for more details."
            error_code = 5
        super().__init__(message, error_code)


def map_catalog_availability_to_exception(
    service_name: str,
    operation_name: str | None,
    support_status: AwsServicesSupportInLatest | AwsServiceOperationsSupportInLatest | None,
) -> AwsServiceAvailabilityException:
    match support_status:
        case AwsServicesSupportInLatest.SUPPORTED | AwsServiceOperationsSupportInLatest.SUPPORTED:
            return LatestVersionRequiredException(service_name, operation_name)
        case (
            AwsServicesSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
            | AwsServiceOperationsSupportInLatest.SUPPORTED_WITH_LICENSE_UPGRADE
        ):
            return LicenseUpgradeRequiredException(service_name, operation_name)
        case AwsServicesSupportInLatest.NOT_SUPPORTED:
            return ServiceNotSupportedException(service_name)
        case _:
            return AwsServiceAvailabilityException(
                message=f"The API for service {service_name} is either not included in your current license plan or has not yet been emulated by LocalStack.",
                error_code=4,
            )
