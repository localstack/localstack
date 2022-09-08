import gzip

from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response

GZIP_STREAM_ATTR = "gzip_stream"
GZIP_CONTENT_ENCODING_ATTR = "gzip_content_encoding"


class ContentDecoder(Handler):
    """
    A handler which takes care of decoding the content of a request (if the header "Content-Encoding" is set).

    The Content-Encoding representation header lists any encodings that have been applied to the representation
    (message payload), and in what order.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Currently, only GZIP is supported. When supporting multiple types, the order needs to be respected
        if context.request.content_encoding and context.request.content_encoding.lower() == "gzip":
            gzip_stream = context.request.stream
            gzip_content_encoding = context.request.headers["Content-Encoding"]

            # wrap the request's stream with GZip decompression (inspired by flask-inflate)
            context.request.stream = gzip.GzipFile(fileobj=gzip_stream)
            context.request.headers["Content-Encoding"] = "identity"

            # Store the original data in case a provider (like S3) needs to access the original data
            setattr(context.request, "gzip_stream", gzip_stream)
            setattr(context.request, "gzip_content_encoding", gzip_content_encoding)
