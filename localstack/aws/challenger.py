import logging
from typing import Optional

from localstack.aws.api import CommonServiceException
from localstack.aws.protocol.serializer import create_serializer
from localstack.aws.protocol.service_router import determine_aws_service_name
from localstack.aws.spec import ServiceCatalog
from localstack.http import Request, Response
from localstack.http.adapters import ProxyListenerAdapter

LOG = logging.getLogger(__name__)

services = ServiceCatalog()


class ServiceNamerParserChallenger(ProxyListenerAdapter):
    def __init__(self, expected: str) -> None:
        super().__init__()
        self.expected = expected

    def to_proxy_response(self, response: Response):
        if response is None:
            return None

        return super().to_proxy_response(response)

    def request(self, request: Request) -> Optional[Response]:
        actual = determine_aws_service_name(request, services)

        if self.expected == actual:
            LOG.info("successful service name match for %s", actual)
            return None

        LOG.error("non-matching service names localstack != asf: %s != %s", self.expected, actual)
        if actual:
            return self._create_error_response(actual)
        else:
            return self._create_error_response(self.expected)

    def _create_error_response(self, service_name: str):
        try:
            service = services.get(service_name)

            # best-effort to return any type of error
            op = service.operation_model(service.operation_names[0])

            exception = CommonServiceException(
                code="ServiceNameParserChallengeFailed",
                status_code=400,
                sender_fault=True,
                message="Service Name Parser Serializer Challenge failed.",
            )
            return create_serializer(service).serialize_error_to_response(exception, op)
        except Exception:
            LOG.exception(
                "exception while trying to create a response. this is an implementation error of the "
                "challenger :("
            )
