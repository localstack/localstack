from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response
from localstack.utils.xray.trace_header import TraceHeader


class TraceContextParser(Handler):
    """
    A handler that parses trace context headers, including:
    * AWS X-Ray trace header: https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # TODO: test capitalization; does lower or mixed case work as well?
        trace_header_str = context.request.headers.get("X-Amzn-Trace-Id")
        # Naming aws_trace_header inspired by AWSTraceHeader convention for SQS:
        # https://docs.aws.amazon.com/xray/latest/devguide/xray-services-sqs.html
        context.trace_context["aws_trace_header"] = TraceHeader.from_header_str(trace_header_str)
