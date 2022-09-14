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


class PatchingLoader(Loader):
    """
    A custom botocore Loader that applies JSON patches from the given json patch file to the specs as they are loaded.
    """

    patches: Dict[str, list]

    def __init__(self, patches: Dict[str, list], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patches = patches

    @instance_cache
    def load_data(self, name: str):
        result = super(PatchingLoader, self).load_data(name)

        if patches := self.patches.get(name):
            return jsonpatch.apply_patch(result, patches)

        return result


loader = PatchingLoader(load_spec_patches())


def list_services(model_type="service-2") -> List[ServiceModel]:
    return [load_service(service) for service in loader.list_available_services(model_type)]


def load_service(service: ServiceName, version: str = None, model_type="service-2") -> ServiceModel:
    """
    For example: load_service("sqs", "2012-11-05")
    """
    service_description = loader.load_service_model(service, model_type, version)
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
    target_prefix_index: Dict[str, List[ServiceName]]
    signing_name_index: Dict[str, List[ServiceName]]
    operations_index: Dict[str, List[ServiceName]]
    endpoint_prefix_index: Dict[str, List[ServiceName]]


class LazyServiceCatalogIndex:
    """
    A ServiceCatalogIndex that builds indexes in-memory from the spec.
    """

    @cached_property
    def service_names(self) -> List[ServiceName]:
        return list(self._services.keys())

    @cached_property
    def target_prefix_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self._services.values():
            target_prefix = service.metadata.get("targetPrefix")
            if target_prefix:
                result[target_prefix].append(service.service_name)
        return dict(result)

    @cached_property
    def signing_name_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self._services.values():
            result[service.signing_name].append(service.service_name)
        return dict(result)

    @cached_property
    def operations_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self._services.values():
            operations = service.operation_names
            if operations:
                for operation in operations:
                    result[operation].append(service.service_name)
        return dict(result)

    @cached_property
    def endpoint_prefix_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self._services.values():
            result[service.endpoint_prefix].append(service.service_name)
        return dict(result)

    @cached_property
    def _services(self) -> Dict[ServiceName, ServiceModel]:
        return {service.service_name: service for service in list_services()}


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
    def target_prefix_index(self) -> Dict[str, List[ServiceName]]:
        return self.index.target_prefix_index

    @property
    def signing_name_index(self) -> Dict[str, List[ServiceName]]:
        return self.index.signing_name_index

    @property
    def operations_index(self) -> Dict[str, List[ServiceName]]:
        return self.index.operations_index

    @property
    def endpoint_prefix_index(self) -> Dict[str, List[ServiceName]]:
        return self.index.endpoint_prefix_index

    def by_target_prefix(self, target_prefix: str) -> List[ServiceName]:
        return self.target_prefix_index.get(target_prefix, [])

    def by_signing_name(self, signing_name: str) -> List[ServiceName]:
        return self.signing_name_index.get(signing_name, [])

    def by_operation(self, operation_name: str) -> List[ServiceName]:
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
