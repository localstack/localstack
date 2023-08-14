from localstack.http import Response
from localstack.services.s3.presigned_url import S3PreSignedURLRequestHandler

from ..api import RequestContext
from ..chain import Handler, HandlerChain


class ParsePreSignedUrlRequest(Handler):
    def __init__(self):
        self.pre_signed_handlers: dict[str, Handler] = {
            "s3": S3PreSignedURLRequestHandler(),
        }

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # TODO: handle other services pre-signed URL (CloudFront)
        if not context.service:
            return

        # we are handling the pre-signed URL before parsing, because S3 will append typical headers parameters to
        # the querystring when generating a pre-signed URL. This handler will move them back into the headers before
        # the parsing of the request happens
        if handler := self.pre_signed_handlers.get(context.service.service_name):
            handler(chain, context, response)
