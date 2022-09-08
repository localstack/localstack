from localstack.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain

ALLOWED_CORS_RESPONSE_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
]


class CorsResponseCleanup(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        headers = response.headers
        # Remove empty CORS headers
        for header in ALLOWED_CORS_RESPONSE_HEADERS:
            if headers.get(header) == "":
                del headers[header]
