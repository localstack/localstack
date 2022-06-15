from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.analytics.response_aggregator import ResponseAggregator


class ResponseAggregatorHandler:
    def __init__(self):
        self.aggregator = ResponseAggregator()
        self.aggregator.start_thread()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if response is None or config.DISABLE_EVENTS:
            return
        self.aggregator.add_response(
            context.service.service_name, context.operation.name, response.status_code
        )
