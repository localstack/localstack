"""
API schema and specifications
"""

from localstack.version import __version__

# OpenAPI schema for the internal API
LOCALSTACK_API = {
    "openapi": "3.2.0",
    "info": {
        "title": "LocalStack REST API for Community Edition",
        "summary": (
            "The LocalStack API exposes functionality related to diagnostics, health checks, plugins, "
            "initialisation hooks, service introspection, and more."
        ),
        "termsOfService": "https://www.localstack.cloud/legal/tos",
        "contact": {
            "url": "https://www.localstack.cloud/contact",
            "email": "info@localstack.cloud",
        },
        "version": __version__,
    },
    "servers": [{"url": "/"}],
    "paths": {
        #
        # Service endpoints. Mind the sorting
        #
        "/_aws/cloudwatch/metrics/raw": {},
        "/_aws/dynamodb/expired": {},
        "/_aws/lambda/runtimes": {},
        "/_aws/ses": {
            "get": {
                "description": "Retrieve all emails sent from SES",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "messages": {
                                            "description": "List of SES messages",
                                            "type": "array",
                                            "items": {"type": "object", "properties": ...},
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
            },
            "delete": {},
        },
        "/_aws/sns/platform-endpoint-messages": {},
        "/_aws/sqs/messages": {},
        #
        # Framework endpoints. Mind the sorting
        #
        "/_localstack/config": {},
        "/_localstack/diagnose": {},
        "/_localstack/health": {},
        "/_localstack/init": {},
        "/_localstack/plugins": {},
    },
}
