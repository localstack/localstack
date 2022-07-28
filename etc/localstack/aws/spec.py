from collections import defaultdict
from functools import cached_property
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
        return self.services.get(name)

    @cached_property
    def services(self) -> Dict[ServiceName, ServiceModel]:
        return {service.service_name: service for service in list_services()}

    @cached_property
    def service_names(self) -> List[ServiceName]:
        return list(self.services.keys())

    @cached_property
    def target_prefix_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self.services.values():
            target_prefix = service.metadata.get("targetPrefix")
            if target_prefix:
                result[target_prefix].append(service.service_name)
        return dict(result)

    @cached_property
    def signing_name_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self.services.values():
            result[service.signing_name].append(service.service_name)
        return dict(result)

    @cached_property
    def operations_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self.services.values():
            operations = service.operation_names
            if operations:
                for operation in operations:
                    result[operation].append(service.service_name)
        return dict(result)

    @cached_property
    def endpoint_prefix_index(self) -> Dict[str, List[ServiceName]]:
        result = defaultdict(list)
        for service in self.services.values():
            result[service.endpoint_prefix].append(service.service_name)
        return dict(result)

    def by_target_prefix(self, target_prefix: str) -> List[ServiceName]:
        return self.target_prefix_index.get(target_prefix, [])

    def by_signing_name(self, signing_name: str) -> List[ServiceName]:
        return self.signing_name_index.get(signing_name, [])

    def by_operation(self, operation_name: str) -> List[ServiceName]:
        return self.operations_index.get(operation_name, [])
