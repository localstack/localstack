import json
import os
from json import JSONDecodeError

from localstack import config, constants
from localstack.utils.catalog.common import AwsRemoteCatalog

AWS_CATALOG_FILE_NAME = "catalog.json"


class AwsCatalogLoaderException(Exception):
    def __init__(self, msg: str, *args):
        super().__init__(msg, *args)


class RemoteCatalogLoader:
    catalog_file_path = os.path.join(config.dirs.cache, AWS_CATALOG_FILE_NAME)

    def get_remote_catalog(self) -> AwsRemoteCatalog:
        pass

    def _load_cached_catalog_if_available(self) -> AwsRemoteCatalog | None:
        pass

    def _parse_catalog(self, document: bytes) -> AwsRemoteCatalog | None:
        try:
            catalog_json = json.loads(document)
        except JSONDecodeError as e:
            raise AwsCatalogLoaderException(f"Could not de-serialize json AWS catalog: {e}") from e

        try:
            if "schema_version" in catalog_json and catalog_json.get("schema_version") != "1":
                raise AwsCatalogLoaderException("Unknown schema version")
            return AwsRemoteCatalog(**catalog_json)
        except (KeyError, ValueError) as e:
            raise AwsCatalogLoaderException(f"Error parsing AWS catalog: {e}") from e

    def _get_catalog(self) -> AwsRemoteCatalog:
        import requests

        from localstack.utils.http import get_proxies

        proxies = get_proxies()
        response = requests.post(
            f"{constants.API_ENDPOINT}/license/catalog",
            verify=not config.is_env_true("SSL_NO_VERIFY"),
            proxies=proxies,
        )

        if response.ok:
            return self._parse_catalog(response.content)
        self._server_error_to_exception(response)

    def _server_error_to_exception(self, response):
        try:
            server_error = response.json()
            if not server_error.get("message"):
                raise AwsCatalogLoaderException(
                    f"Unexpected AWS catalog server error: {response.text}"
                )
            message = server_error["message"]
            raise AwsCatalogLoaderException(f"Unexpected AWS catalog server error: {message}")
        except Exception:
            raise AwsCatalogLoaderException(f"Unexpected AWS catalog server error: {response.text}")
