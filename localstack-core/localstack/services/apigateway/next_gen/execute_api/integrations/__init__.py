from .aws import RestApiAwsIntegration, RestApiAwsProxyIntegration
from .http import RestApiHttpIntegration, RestApiHttpProxyIntegration
from .mock import RestApiMockIntegration

REST_API_INTEGRATIONS = {
    RestApiAwsIntegration.name: RestApiAwsIntegration(),
    RestApiAwsProxyIntegration.name: RestApiAwsProxyIntegration(),
    RestApiHttpIntegration.name: RestApiHttpIntegration(),
    RestApiHttpProxyIntegration.name: RestApiHttpProxyIntegration(),
    RestApiMockIntegration.name: RestApiMockIntegration(),
}

__all__ = [
    "REST_API_INTEGRATIONS",
]
