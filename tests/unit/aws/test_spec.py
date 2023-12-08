from botocore.model import ServiceModel, StringShape

from localstack.aws.spec import (
    CustomLoader,
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


def test_patching_loaders():
    # first test that specs remain intact
    loader = CustomLoader({})
    description = loader.load_service_model("s3", "service-2")

    model = ServiceModel(description, "s3")

    shape = model.shape_for("NoSuchBucket")
    # by default, the s3 error shapes have no members, but AWS will actually return additional attributes
    assert not shape.members
    assert shape.metadata.get("exception")

    # now try it with a patch
    loader = CustomLoader(
        {
            "s3/2006-03-01/service-2": [
                {
                    "op": "add",
                    "path": "/shapes/NoSuchBucket/members/BucketName",
                    "value": {"shape": "BucketName"},
                },
                {
                    "op": "add",
                    "path": "/shapes/NoSuchBucket/error",
                    "value": {"httpStatusCode": 404},
                },
            ],
        }
    )
    description = loader.load_service_model("s3", "service-2", "2006-03-01")
    model = ServiceModel(description, "s3")

    shape = model.shape_for("NoSuchBucket")
    assert "BucketName" in shape.members
    assert isinstance(shape.members["BucketName"], StringShape)
    assert shape.metadata["error"]["httpStatusCode"] == 404
    assert shape.metadata.get("exception")


def test_loading_own_specs():
    """Ensure that the internalized specifications (f.e. the sqs-query spec) can be handled by the CustomLoader."""
    loader = CustomLoader({})
    # first test that specs remain intact
    sqs_query_description = loader.load_service_model("sqs-query", "service-2")
    assert sqs_query_description["metadata"]["protocol"] == "query"
    sqs_json_description = loader.load_service_model("sqs", "service-2")
    assert sqs_json_description["metadata"]["protocol"] == "json"
