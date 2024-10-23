import asyncio
import multiprocessing as mp
from threading import Thread

from rolo.gateway.wsgi import WsgiGateway

from localstack.aws.api import RequestContext
from localstack.aws.app import LocalstackAwsGateway

ev = mp.Event()


def create_app():
    loop = asyncio.new_event_loop()
    gateway = LocalstackAwsGateway()

    def f(_loop):
        asyncio.set_event_loop(_loop)
        _loop.run_forever()

    t = Thread(target=f, args=(loop,))
    t.daemon = True
    t.start()

    def _add_loop_context(_, context: RequestContext, __):
        context._loop = loop

    gateway.request_handlers.insert(0, _add_loop_context)

    app = WsgiGateway(gateway)
    return app


# SQS_DISABLE_CLOUDWATCH_METRICS=1 SERVICES=sqs python -m gunicorn --bind 0.0.0.0:4566 -w 10 "localstack.aws.serving.gunicorn:create_app()"
