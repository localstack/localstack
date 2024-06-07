from rolo import Request
from rolo.gateway import RequestContext


class InvocationContext(RequestContext):
    """
    This context is going to be used to pass relevant information across an API Gateway invocation.
    """

    def __init__(self, request: Request):
        super().__init__(request)
