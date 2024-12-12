from localstack.feature_catalog.service_feature import (
    ApiCoverage,
    ImplementationStatus,
    SupportStatus,
)


class CreateKey(ApiCoverage):
    """
    One suggestions on how to track specific api-operation limitations:

    Alternative solution would be using the ApiLimitation (file feature_catalog/api_limitation.py), which provides a more generic way
    of doing so
    """

    general_docs: str = "Creates an AWS KMS key."
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: list = [
        "Status 'Updating' is not supported.",
    ]
