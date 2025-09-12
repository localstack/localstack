import json

from pydantic import BaseModel

LICENSE_CATALOG_PATH = ""


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


class RemoteCatalogLoader:
    def get_remote_catalog(self) -> AwsRemoteCatalog:
        with open(LICENSE_CATALOG_PATH) as f:
            return AwsRemoteCatalog(
                **json.load(f)
            )  # TODO: catch exceptions and fallback to default catalog
