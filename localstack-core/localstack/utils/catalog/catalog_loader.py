import json

from localstack.utils.catalog.common import AwsRemoteCatalog

LICENSE_CATALOG_PATH = ""


class RemoteCatalogLoader:
    def get_remote_catalog(self) -> AwsRemoteCatalog:
        with open(LICENSE_CATALOG_PATH) as f:
            return AwsRemoteCatalog(**json.load(f))
