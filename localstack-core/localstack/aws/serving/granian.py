from rolo.gateway.wsgi import WsgiGateway

from localstack.aws.app import LocalstackAwsGateway
from localstack.logging.setup import setup_logging_from_config

# from localstack.runtime.current import initialize_runtime


def create_app():
    # gateway = initialize_runtime().components.gateway
    gateway = LocalstackAwsGateway()
    setup_logging_from_config()

    app = WsgiGateway(gateway)
    return app


# granian --interface wsgi --factory --port 4566 --threads 10 localstack.aws.serving.granian:create_app
