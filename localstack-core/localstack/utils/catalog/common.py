from enum import StrEnum

from pydantic import BaseModel


class CloudFormationResource(BaseModel):
    methods: list[str]


class AwsServiceCatalog(BaseModel):
    provider: str
    operations: list[str]
    plans: list[str]


class LocalStackMetadata(BaseModel):
    version: str


class AwsRemoteCatalog(BaseModel):
    schema_version: str
    localstack: LocalStackMetadata
    services: dict[str, dict[str, AwsServiceCatalog]]
    cloudformation_resources: dict[str, dict[str, CloudFormationResource]]


class LocalstackEmulatorType(StrEnum):
    COMMUNITY = "community"
    PRO = "pro"


class AwsServiceSupportAtRuntime(StrEnum):
    AVAILABLE = "AVAILABLE"
    AVAILABLE_WITH_LICENSE_UPGRADE = "AVAILABLE_WITH_LICENSE_UPGRADE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class AwsServicesSupportInLatest(StrEnum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_LICENSE_UPGRADE = "SUPPORTED_WITH_LICENSE_UPGRADE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NON_DEFAULT_PROVIDER = "NON_DEFAULT_PROVIDER"


class AwsServiceOperationsSupportInLatest(StrEnum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_LICENSE_UPGRADE = "SUPPORTED_WITH_LICENSE_UPGRADE"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class CloudFormationResourcesSupportInLatest(StrEnum):
    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class CloudFormationResourcesSupportAtRuntime(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
