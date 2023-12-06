import dataclasses
import json
import os
from collections import defaultdict
from functools import cached_property, lru_cache
from typing import Dict, Generator, List, Optional, Tuple

import jsonpatch
from botocore.loaders import Loader, instance_cache
from botocore.model import OperationModel, ServiceModel

ServiceName = str

spec_patches_json = os.path.join(os.path.dirname(__file__), "spec-patches.json")


def load_spec_patches() -> Dict[str, list]:
    if not os.path.exists(spec_patches_json):
        return {}
    with open(spec_patches_json) as fd:
        return json.load(fd)


# Path for custom specs which are not (anymore) provided by botocore
LOCALSTACK_BUILTIN_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


class LocalStackBuiltInDataLoaderMixin(Loader):
    def __init__(self, *args, **kwargs):
        # add the builtin data path to the extra_search_paths to ensure they are discovered by the loader
        super().__init__(*args, extra_search_paths=[LOCALSTACK_BUILTIN_DATA_PATH], **kwargs)


class PatchingLoader(Loader):
    """
    A custom botocore Loader that applies JSON patches from the given json patch file to the specs as they are loaded.
    """

    patches: Dict[str, list]

    def __init__(self, patches: Dict[str, list], *args, **kwargs):
        # add the builtin data path to the extra_search_paths to ensure they are discovered by the loader
        super().__init__(*args, **kwargs)
        self.patches = patches

    @instance_cache
    def load_data(self, name: str):
        result = super(PatchingLoader, self).load_data(name)

        if patches := self.patches.get(name):
            return jsonpatch.apply_patch(result, patches)

        return result


class CustomLoader(PatchingLoader, LocalStackBuiltInDataLoaderMixin):
    # Class mixing the different loader features (patching, localstack specific data)
    pass


loader = CustomLoader(load_spec_patches())


def list_services(model_type="service-2") -> List[ServiceModel]:
    return [load_service(service) for service in loader.list_available_services(model_type)]


def load_service(service: ServiceName, version: str = None, model_type="service-2") -> ServiceModel:
    """
    For example: load_service("sqs", "2012-11-05")
    """
    service_description = loader.load_service_model(service, model_type, version)
    # if the service name is sqs-json, we just loaded our internalized SQS query spec,
    # the service name needs to be set to standard sqs
    if service == "sqs-json":
        service = "sqs"
    return ServiceModel(service_description, service)


def iterate_service_operations() -> Generator[Tuple[ServiceModel, OperationModel], None, None]:
    """
    Returns one record per operation in the AWS service spec, where the first item is the service model the operation
    belongs to, and the second is the operation model.

    :return: an iterable
    """
    for service in list_services():
        for op_name in service.operation_names:
            yield service, service.operation_model(op_name)


@dataclasses.dataclass
class ServiceCatalogIndex:
    """
    The ServiceCatalogIndex enables fast lookups for common operations to determine a service from service indicators.
    """

    service_names: List[ServiceName]
    target_prefix_index: Dict[str, List[ServiceModel]]
    signing_name_index: Dict[str, List[ServiceModel]]
    operations_index: Dict[str, List[ServiceModel]]
    endpoint_prefix_index: Dict[str, List[ServiceModel]]


class LazyServiceCatalogIndex:
    """
    A ServiceCatalogIndex that builds indexes in-memory from the spec.
    """

    @cached_property
    def service_names(self) -> List[ServiceName]:
        return list(self._services.keys())

    @cached_property
    def target_prefix_index(self) -> Dict[str, List[ServiceModel]]:
        result = defaultdict(list)
        for service_models in self._services.values():
            for service_model in service_models:
                target_prefix = service_model.metadata.get("targetPrefix")
                if target_prefix:
                    result[target_prefix].append(service_model)
        return dict(result)

    @cached_property
    def signing_name_index(self) -> Dict[str, List[ServiceModel]]:
        result = defaultdict(list)
        for service_models in self._services.values():
            for service_model in service_models:
                result[service_model.signing_name].append(service_model)
        return dict(result)

    @cached_property
    def operations_index(self) -> Dict[str, List[ServiceModel]]:
        result = defaultdict(list)
        for service_models in self._services.values():
            for service_model in service_models:
                operations = service_model.operation_names
                if operations:
                    for operation in operations:
                        result[operation].append(service_model)
        return dict(result)

    @cached_property
    def endpoint_prefix_index(self) -> Dict[str, List[ServiceModel]]:
        result = defaultdict(list)
        for service_models in self._services.values():
            for service_model in service_models:
                result[service_model.endpoint_prefix].append(service_model)
        return dict(result)

    @cached_property
    def _services(self) -> Dict[ServiceName, List[ServiceModel]]:
        services = defaultdict(list)
        for service in list_services():
            services[service.service_name].append(service)
        return services


class ServiceCatalog:
    index: ServiceCatalogIndex

    def __init__(self, index: ServiceCatalogIndex = None):
        self.index = index or LazyServiceCatalogIndex()

    @lru_cache(maxsize=512)
    def get(self, name: ServiceName) -> Optional[ServiceModel]:
        return load_service(name)

    @property
    def service_names(self) -> List[ServiceName]:
        return self.index.service_names

    @property
    def target_prefix_index(self) -> Dict[str, List[ServiceModel]]:
        return self.index.target_prefix_index

    @property
    def signing_name_index(self) -> Dict[str, List[ServiceModel]]:
        return self.index.signing_name_index

    @property
    def operations_index(self) -> Dict[str, List[ServiceModel]]:
        return self.index.operations_index

    @property
    def endpoint_prefix_index(self) -> Dict[str, List[ServiceModel]]:
        return self.index.endpoint_prefix_index

    def by_target_prefix(self, target_prefix: str) -> List[ServiceModel]:
        return self.target_prefix_index.get(target_prefix, [])

    def by_signing_name(self, signing_name: str) -> List[ServiceModel]:
        return self.signing_name_index.get(signing_name, [])

    def by_operation(self, operation_name: str) -> List[ServiceModel]:
        return self.operations_index.get(operation_name, [])


def build_service_index_cache(file_path: str) -> ServiceCatalogIndex:
    """
    Creates a new ServiceCatalogIndex and stores it into the given file_path.

    :param file_path: the path to pickle to
    :return: the created ServiceCatalogIndex
    """
    return save_service_index_cache(LazyServiceCatalogIndex(), file_path)


def load_service_index_cache(file: str) -> ServiceCatalogIndex:
    """
    Loads from the given file the pickled ServiceCatalogIndex.

    :param file: the file to load from
    :return: the loaded ServiceCatalogIndex
    """
    import pickle

    with open(file, "rb") as fd:
        return pickle.load(fd)


def save_service_index_cache(index: LazyServiceCatalogIndex, file_path: str) -> ServiceCatalogIndex:
    """
    Creates from the given LazyServiceCatalogIndex a ``ServiceCatalogIndex`, pickles its contents into the given file,
    and then returns the newly created index.

    :param index: the LazyServiceCatalogIndex to store the index from.
    :param file_path: the path to pickle to
    :return: the created ServiceCatalogIndex
    """
    import pickle

    cache = ServiceCatalogIndex(
        service_names=index.service_names,
        endpoint_prefix_index=index.endpoint_prefix_index,
        operations_index=index.operations_index,
        signing_name_index=index.signing_name_index,
        target_prefix_index=index.target_prefix_index,
    )
    with open(file_path, "wb") as fd:
        pickle.dump(cache, fd)
    return cache
