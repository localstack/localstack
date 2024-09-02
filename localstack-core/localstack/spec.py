"""
API specifications and schema.
"""

from typing import Final

from localstack.version import __version__

# OpenAPI specification for the internal REST API
OPENAPI: Final = {
    "openapi": "3.1.0",
    "info": {
        "title": "LocalStack REST API for Community Edition",
        "summary": (
            "The LocalStack REST API exposes functionality related to diagnostics, health checks, plugins, "
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
                "description": "Retrieve sent emails",
                "responses": {
                    "200": {
                        "description": "List of sent emails",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "messages": {
                                            "description": "List of sent SES messages",
                                            "type": "array",
                                            "items": {"type": "object", "properties": {}},
                                        }
                                    },
                                }
                            }
                        },
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
        "/_localstack/health": {
            "get": {
                "parameters": [
                    {
                        "name": "reload",
                        "in": "query",
                        "allowEmptyValue": True,
                        "schema": {
                            "type": "string",
                        },
                        "required": False,
                    }
                ],
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "edition": {
                                            "type": "string",
                                            "enum": ["community", "pro", "enterprise"],
                                        },
                                        "features": {
                                            "type": "object",
                                        },
                                        "services": {
                                            "type": "object",
                                        },
                                        "version": {
                                            "type": "string",
                                        },
                                    },
                                }
                            }
                        },
                    }
                },
            },
            "head": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {"text/plain": {}},
                    }
                }
            },
            "post": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {"text/plain": {}},
                    }
                },
                "requestBody": {
                    "description": "",  # TODO
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "action": {"type": "string", "enum": ["restart", "kill"]}
                                },
                            }
                        }
                    },
                    "required": True,
                },
            },
            "put": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"status": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
                "requestBody": {
                    "description": "",  # TODO
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                            }
                        }
                    },
                },
            },
        },
        "/_localstack/info": {},
        "/_localstack/init": {},
        "/_localstack/init/{stage}": {},
        "/_localstack/plugins": {},
        "/_localstack/stackinfo": {
            "get": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "server_time_utc": {"type": "string"},
                                        "session_id": {"type": "string"},
                                        "api_key": {"type": "string"},
                                        "system": {"type": "string"},
                                        "version": {"type": "string"},
                                        "is_ci": {"type": "boolean"},
                                        "is_docker": {"type": "boolean"},
                                        "duration_in_seconds": {"type": "integer"},
                                        "top_user_agent": {"type": "string"},
                                        "number_of_services": {"type": "integer"},
                                        "number_of_api_calls_success": {"type": "integer"},
                                        "number_of_api_calls_error": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    }
                }
            }
        },
        "/_localstack/usage": {},
    },
}
