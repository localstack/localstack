from typing import List

from botocore.loaders import create_loader
from botocore.model import ServiceModel

loader = create_loader()


def list_services(model_type="service-2") -> List[ServiceModel]:
    return [load_service(service) for service in loader.list_available_services(model_type)]


def load_service(service: str, version: str = None, model_type="service-2") -> ServiceModel:
    """
    For example: load_service("sqs", "2012-11-05")
    """
    service_description = loader.load_service_model(service, model_type, version)
    return ServiceModel(service_description, service)
