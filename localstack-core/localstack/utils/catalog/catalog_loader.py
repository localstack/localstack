import json
import logging
from json import JSONDecodeError
from pathlib import Path

import requests

from localstack import config, constants
from localstack.utils.catalog.common import AwsRemoteCatalog
from localstack.utils.json import FileMappedDocument

LOG = logging.getLogger(__name__)

AWS_CATALOG_FILE_NAME = "aws_catalog.json"


class AwsCatalogLoaderException(Exception):
    def __init__(self, msg: str, *args):
        super().__init__(msg, *args)


class RemoteCatalogLoader:
    api_endpoint_catalog = f"{constants.API_ENDPOINT}/license/catalog"
    catalog_file_path = Path(config.dirs.cache) / AWS_CATALOG_FILE_NAME

    def get_remote_catalog(self) -> AwsRemoteCatalog:
        catalog_doc = FileMappedDocument(self.catalog_file_path)
        cached_catalog = AwsRemoteCatalog(**catalog_doc) if catalog_doc else None
        if cached_catalog:
            cached_catalog_version = cached_catalog.localstack.version
            if not self._should_update_cached_catalog(cached_catalog_version):
                return cached_catalog
        catalog = self._get_catalog_from_platform()
        self._save_catalog_to_cache(catalog_doc, catalog)
        return catalog

    def _get_latest_localstack_version(self) -> str:
        pass

    def _should_update_cached_catalog(self, current_catalog_version: str) -> bool:
        try:
            latest_version = self._get_latest_localstack_version()
            return latest_version != current_catalog_version
        except Exception as e:
            LOG.warning(
                "Failed to retrieve the latest catalog version, cached catalog update skipped: %s",
                e,
            )
            return False

    def _save_catalog_to_cache(self, catalog_doc: FileMappedDocument, catalog: AwsRemoteCatalog):
        catalog_doc.clear()
        catalog_doc.update(catalog.model_dump())
        catalog_doc.save()

    def _get_catalog_from_platform(self) -> AwsRemoteCatalog | None:
        import requests

        from localstack.utils.http import get_proxies

        try:
            proxies = get_proxies()
            response = requests.post(
                self.api_endpoint_catalog,
                verify=not config.is_env_true("SSL_NO_VERIFY"),
                proxies=proxies,
            )

            if response.ok:
                return self._parse_catalog(response.content)
            self._raise_server_error(response)
        except requests.exceptions.RequestException as e:
            raise AwsCatalogLoaderException(
                f"An unexpected network error occurred when trying to fetch remote catalog: {e}"
            ) from e

    def _parse_catalog(self, document: bytes) -> AwsRemoteCatalog | None:
        try:
            catalog_json = json.loads(document)
        except JSONDecodeError as e:
            raise AwsCatalogLoaderException(f"Could not de-serialize json catalog: {e}") from e
        remote_catalog = AwsRemoteCatalog(**catalog_json)
        if remote_catalog.schema_version != "v1":
            raise AwsCatalogLoaderException(
                f"Unsupported schema version: {remote_catalog.schema_versio}"
            )
        return remote_catalog

    def _raise_server_error(self, response: requests.Response):
        try:
            server_error = response.json()
            if not server_error.get("message"):
                raise AwsCatalogLoaderException(
                    f"Unexpected AWS catalog server error: {response.text}"
                )
            message = server_error["message"]
            raise AwsCatalogLoaderException(
                f"An unexpected server error occurred when trying to fetch remote catalog: {message}"
            )
        except Exception:
            raise AwsCatalogLoaderException(
                f"An unexpected server error occurred when trying to fetch remote catalog: {response.text}"
            )
