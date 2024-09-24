import requests
from botocore.auth import BaseSigner
from botocore.awsrequest import AWSRequest


class SigningHttpClient:
    """
    A wrapper around ``requests`` that uses botocore to sign HTTP requests using a ``botocore.auth.BaseSigner``.

    For example, using a Sig4QueryAuth signer, invocations to ``client.get(
    "http://localhost:4566/000000000000/test-queue")`` it will transparently change the URL to something like:

    http://localhost:4566/000000000000/test-queue
        ?X-Amz-Algorithm=AWS4-HMAC-SHA256
        &X-Amz-Credential=__test_call__%2F20220513%2Fus-east-1%2Fsqs%2Faws4_request
        &X-Amz-Date=20220513T192006Z
        &X-Amz-Expires=3600
        &X-Amz-SignedHeaders=host
        &X-Amz-Signature=ae39eb839d0501d731d5dccffd1e6e86fab53749f956caabbb8211b6593f5f9d

    You can also create a client with an endpoint_url set, where you can then make requests with the hostname part.
    For example, to create a raw GetQueueUrl request, run:

       client = SigningHttpClient(signer, endpoint_url="https://sqs.us-east-1.amazonaws.com")
       client.post("/", params={"Action", "GetQueueUrl", "QueueName": "my-queue"})
    """

    def __init__(
        self, signer: BaseSigner, session: requests.Session = None, endpoint_url: str = None
    ):
        self.signer = signer
        self.session = session or requests.Session()
        self.endpoint_url = endpoint_url

    def request(self, method, url, **kwargs) -> requests.Response:
        if url.startswith("/"):
            if not self.endpoint_url:
                raise ValueError("no hostname provided in url and no endpoint_url set")

            url = self.endpoint_url.rstrip("/") + url

        request = AWSRequest(
            method=method,
            url=url,
            data=kwargs.pop("data", None),
            params=kwargs.pop("params", None),
            headers=kwargs.pop("headers", None),
        )
        request = self.sign(request)

        url = request.url
        method = request.method

        kwargs["data"] = request.data
        kwargs["params"] = request.params
        kwargs["headers"] = request.headers

        return self.session.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def sign(self, request: AWSRequest) -> AWSRequest:
        self.signer.add_auth(request)
        return request
