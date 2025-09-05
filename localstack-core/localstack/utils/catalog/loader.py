import json

from pydantic import BaseModel

LICENSE_CATALOG_PATH = ""


class AwsRemoteCatalog(BaseModel):
    schema_version: str
    localstack: dict[str, str]
    services: dict[str, dict]
    cloudformation_resources: dict[str, dict]


class RemoteCatalogLoader:
    def get_remote_catalog(self) -> AwsRemoteCatalog:
        with open(LICENSE_CATALOG_PATH) as f:
            return AwsRemoteCatalog(
                **json.load(f)
            )  # TODO: catch exceptions and fallback to default catalog
