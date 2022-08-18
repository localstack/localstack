from localstack.aws.spec import (
    LazyServiceCatalogIndex,
    load_service_index_cache,
    save_service_index_cache,
)


def test_pickled_index_equals_lazy_index(tmp_path):
    file_path = tmp_path / "index-cache.pickle"

    lazy_index = LazyServiceCatalogIndex()

    save_service_index_cache(lazy_index, str(file_path))
    cached_index = load_service_index_cache(str(file_path))

    assert cached_index.service_names == lazy_index.service_names
    assert cached_index.target_prefix_index == lazy_index.target_prefix_index
    assert cached_index.signing_name_index == lazy_index.signing_name_index
    assert cached_index.operations_index == lazy_index.operations_index
    assert cached_index.endpoint_prefix_index == lazy_index.endpoint_prefix_index
