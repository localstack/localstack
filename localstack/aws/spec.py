import dataclasses
from collections import defaultdict
from functools import cached_property, lru_cache
from typing import Dict, Generator, List, Optional, Tuple

from botocore.loaders import create_loader
from botocore.model import OperationModel, ServiceModel

loader = create_loader()

ServiceName = str


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


class ServiceCatalog:
    def get(self, name: ServiceName) -> Optional[ServiceModel]:
        return self._services.get(name)

    def by_target_prefix(self, target_prefix: str) -> List[ServiceName]:
        return self.target_prefix_index.get(target_prefix, [])

    def by_signing_name(self, signing_name: str) -> List[ServiceName]:
        return self.signing_name_index.get(signing_name, [])

    def by_operation(self, operation_name: str) -> List[ServiceName]:
        return self.operations_index.get(operation_name, [])

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
        # since index creation requires all services to be loaded, we implement this method here
        # to load and cache all services up front, and then let .get access this cache as well.
        return {service.service_name: service for service in list_services()}


@dataclasses.dataclass
class ServiceCatalogIndex:
    service_names: List[ServiceName]
    endpoint_prefix_index: Dict[str, List[ServiceName]]
    operations_index: Dict[str, List[ServiceName]]
    signing_name_index: Dict[str, List[ServiceName]]
    target_prefix_index: Dict[str, List[ServiceName]]


class CachedServiceCatalog(ServiceCatalog):
    """
    A ServiceCatalog that uses a pre-built ServiceCatalogIndex instead of resolving the indices
    lazily at runtime from the specifications.
    """

    index: ServiceCatalogIndex

    def __init__(self, index: ServiceCatalogIndex):
        self.index = index

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


def save_service_index_cache(catalog: ServiceCatalog, file_path: str) -> ServiceCatalogIndex:
    """
    Extracts from the given ServiceCatalog a ServiceCatalogIndex and pickles that into the given file.
    :param catalog: the catalog that creates the service-operation indexes.
    :param file_path: the path to pickle to
    :return: the created ServiceCatalogIndex
    """
    import pickle

    cache = ServiceCatalogIndex(
        catalog.service_names,
        catalog.endpoint_prefix_index,
        catalog.operations_index,
        catalog.signing_name_index,
        catalog.target_prefix_index,
    )
    with open(file_path, "wb") as fd:
        pickle.dump(cache, fd)
    return cache


def load_service_index_cache(file: str) -> ServiceCatalogIndex:
    """
    Loads from the given file the pickled ServiceCatalogIndex.

    :param file: the file to load from
    :return: the loaded ServiceCatalogIndex
    """
    import pickle

    with open(file, "rb") as fd:
        return pickle.load(fd)
