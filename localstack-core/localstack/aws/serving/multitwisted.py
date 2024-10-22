import dataclasses
import json

from orjson import orjson

from localstack.aws.api import ServiceException
from localstack.aws.skeleton import create_dispatch_table
from localstack.services.sqs.provider import SqsProvider


@dataclasses.dataclass
class FakeRequest:
    scheme: str


fake_req = FakeRequest(scheme="http")


@dataclasses.dataclass
class FakeOperation:
    name: str


@dataclasses.dataclass
class FakeService:
    protocol: str


@dataclasses.dataclass
class JsonContext:
    account_id: str
    region: str
    request_id: str
    partition: str
    operation: FakeOperation
    service: FakeService
    request: FakeRequest


class ServiceWsgiApp:
    def __init__(self, provider):
        self.provider = provider
        self._dispatch_table = create_dispatch_table(provider)

    def _invoke_orjson(self, payload: bytes):
        req = orjson.loads(payload)
        context = JsonContext(**req["context"], request=fake_req)
        context.service = FakeService(**context.service)
        context.operation = FakeOperation(**context.operation)

        instance = req["instance"]
        handler = self._dispatch_table[context.operation.name]
        try:
            response = {"response": handler(context, instance)}
        except ServiceException as e:
            # we could serialize something somewhat here?
            response = {"error": e.to_dict()}
        return json.dumps(response).encode("utf-8")

    def __call__(self, environ, start_response):
        content_length = int(environ["CONTENT_LENGTH"])
        input = environ["wsgi.input"].read(content_length)
        _invoke_result = self._invoke_orjson(input)
        status = "200 OK"
        response_headers = [("Content-type", "application/json")]
        start_response(status, response_headers)
        return [_invoke_result]


def wsgi_app():
    provider = SqsProvider()
    # provider.on_after_init()
    # provider.on_before_start()
    return ServiceWsgiApp(provider)
