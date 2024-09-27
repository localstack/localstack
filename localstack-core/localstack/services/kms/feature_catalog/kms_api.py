from localstack.feature_catalog.service_feature import (
    ApiCoverage,
    ImplementationStatus,
    SupportStatus,
)


class CreateKey(ApiCoverage):
    general_docs: str = "Creates an AWS KMS key."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: list = [
        "Status 'Updating' is not supported.",
    ]
