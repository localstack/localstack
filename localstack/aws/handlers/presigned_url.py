from localstack.http import Response
from localstack.services.s3.presigned_url import s3_presigned_url_request_handler

from ..api import RequestContext
from ..chain import Handler, HandlerChain


class ParsePreSignedUrlRequest(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # TODO: handle other services pre-signed URL (CloudFront)
        if not context.service:
            return

        # we are handling the pre-signed URL before parsing, because S3 will append typical headers parameters to
        # the querystring when generating a pre-signed URL. This handler will move them back into the headers before
        # the parsing of the request happens
        if context.service.service_name != "s3":
            s3_presigned_url_request_handler(chain, context, response)
