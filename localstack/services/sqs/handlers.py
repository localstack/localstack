from urllib.parse import urlencode

from localstack.aws.api import HttpRequest, HttpResponse, RequestContext
from localstack.aws.chain import Handler, HandlerChain

from .sqs_listener import is_sqs_queue_url


class SqsQueueActionHandler(Handler):
    """
    SQS allows GET requests directly on queue URLs. However, such requests cannot be parsed by the ASF. This handler
    transforms a GET request to a Queue URL into a POST request that can be dispatched to the SQS provider by ASF.
    """

    def is_sqs_queue_url(self, url: str) -> bool:
        # FIXME: it would be better to register URLs when queues are created and match against the paths, rather than
        #  guessing it from the URL pattern every time (regex match is expensive and will be done for every request).
        return is_sqs_queue_url(url)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        request = context.request

        if not self.is_sqs_queue_url(request.url):
            return

        # this request is to a Queue directly, modify the request to make it parseable to the ASF.
        headers = request.headers
        if not headers.get("Authorization"):
            from localstack.utils.aws import aws_stack

            headers["Authorization"] = aws_stack.mock_aws_request_headers(service="sqs")[
                "Authorization"
            ]

        if not request.values:
            # TODO: this behavior was copied from the old SQS implementation, but this is not how AWS behaves
            queue_name = request.path.split("/")[-1]
            body = f"Action=GetQueueUrl&QueueName={queue_name}"
        else:
            values = request.values.copy()
            values["QueueUrl"] = request.url
            body = urlencode(values)

        request = HttpRequest(
            method="POST",
            path="/",
            body=body,
            headers=request.headers,
            scheme=request.scheme,
            remote_addr=request.remote_addr,
        )
        context.request = request
