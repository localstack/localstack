import json

import pydantic
import pytest

from localstack.utils.catalog.catalog_loader import AwsCatalogLoaderException, RemoteCatalogLoader
from localstack.utils.catalog.common import AwsRemoteCatalog
from localstack.utils.json import FileMappedDocument
from tests.unit.utils.catalog.conftest import CATALOG


class TestCatalogLoader:
    def test_parse_valid_catalog(self):
        catalog_loader = RemoteCatalogLoader()
        assert catalog_loader._parse_catalog(CATALOG.json().encode()) == CATALOG

    def test_parse_catalog_with_missing_key(self):
        catalog_loader = RemoteCatalogLoader()
        catalog = CATALOG.dict()
        catalog.pop("localstack")
        with pytest.raises(pydantic.ValidationError):
            catalog_loader._parse_catalog(json.dumps(catalog).encode())

    def test_parse_catalog_with_invalid_json(self):
        with pytest.raises(AwsCatalogLoaderException, match="Could not de-serialize json catalog"):
            RemoteCatalogLoader()._parse_catalog(b'{"invalid": json content')

    def test_save_catalog_to_cache(self, tmp_path):
        path = tmp_path / "test_catalog.json"
        catalog_doc = FileMappedDocument(path)
        catalog_loader = RemoteCatalogLoader()
        catalog_doc.update(
            CATALOG.model_dump() | {"localstack": {"version": "v1.1"}, "key1": "value1"}
        )

        assert "key1" in catalog_doc
        assert catalog_doc["localstack"]["version"] == "v1.1"

        catalog_loader._save_catalog_to_cache(catalog_doc, CATALOG)

        catalog_doc.load()
        assert AwsRemoteCatalog(**catalog_doc) == CATALOG
