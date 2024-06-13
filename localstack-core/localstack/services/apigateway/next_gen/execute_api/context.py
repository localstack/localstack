from typing import Optional

from rolo import Request
from rolo.gateway import RequestContext

from localstack.services.apigateway.models import RestApiDeployment


class RestApiInvocationContext(RequestContext):
    """
    This context is going to be used to pass relevant information across an API Gateway invocation.
    """

    deployment: Optional[RestApiDeployment]
    api_id: Optional[str]
    stage: Optional[str]

    def __init__(self, request: Request):
        super().__init__(request)
        self.deployment = None
        self.api_id = None
        self.stage = None
