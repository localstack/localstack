from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response
from localstack.utils.xray.trace_header import TraceHeader


class TraceContextParser(Handler):
    """
    A handler that parses trace context headers, including:
    * AWS X-Ray trace header: https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader
      X-Amzn-Trace-Id: Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1;Lineage=a87bd80c:1|68fd508a:5|c512fbe3:2
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # The Werkzeug headers data structure handles case-insensitive HTTP header matching (verified manually)
        trace_header_str = context.request.headers.get("X-Amzn-Trace-Id")
        # The minimum X-Ray header only contains a Root trace id, missing Sampled and Parent
        aws_trace_header = TraceHeader.from_header_str(trace_header_str).ensure_root_exists()
        # Naming aws_trace_header inspired by AWSTraceHeader convention for SQS:
        # https://docs.aws.amazon.com/xray/latest/devguide/xray-services-sqs.html
        context.trace_context["aws_trace_header"] = aws_trace_header
        # NOTE: X-Ray sampling might require service-specific decisions:
        #  https://docs.aws.amazon.com/xray/latest/devguide/xray-console-sampling.html
