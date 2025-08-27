from localstack.utils.catalog.plugins import CatalogPlugin


class AwsCatalogPlugin(CatalogPlugin):
    name = "aws_catalog"

    def load(self, *args, **kwargs):
        from localstack.utils.catalog.catalog import AwsCatalog

        return AwsCatalog
