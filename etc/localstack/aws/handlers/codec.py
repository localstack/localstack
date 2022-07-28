import gzip

from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response


class ContentDecoder(Handler):
    """
    A handler which takes care of decoding the content of a request (if the header "Content-Encoding" is set).

    The Content-Encoding representation header lists any encodings that have been applied to the representation
    (message payload), and in what order.
    """

    # Some services _break_ the specification of Content-Encoding (f.e. in combination with Content-MD5).
    SKIP_GZIP_SERVICES = ["s3"]

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if context.service and context.service.service_name in self.SKIP_GZIP_SERVICES:
            # Skip the decoding for services which need to do this on their own
            return

        # Currently, only GZIP is supported. When supporting multiple types, the order needs to be respected
        if context.request.content_encoding and context.request.content_encoding.lower() == "gzip":
            # wrap the request's stream with GZip decompression (inspired by flask-inflate)
            context.request.stream = gzip.GzipFile(fileobj=context.request.stream)
            context.request.headers["Content-Encoding"] = "identity"
