import asyncio
import itertools
import multiprocessing as mp

from rolo.gateway.wsgi import WsgiGateway

from localstack.aws.api import RequestContext
from localstack.aws.app import LocalstackAwsGateway

ev = mp.Event()


def create_app():
    counter = itertools.count()

    def call_count():
        return next(counter)

    loop = asyncio.new_event_loop()
    gateway = LocalstackAwsGateway()

    def _add_loop_context(_, context: RequestContext, __):
        context._loop = loop
        call_count()

    gateway.request_handlers.insert(0, _add_loop_context)

    app = WsgiGateway(gateway)
    return app


# SQS_DISABLE_CLOUDWATCH_METRICS=1 python -m gunicorn --bind 0.0.0.0:4566 -w 10 "localstack.aws.serving.gunicorn:create_app()"
