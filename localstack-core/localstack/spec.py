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
    "externalDocs": {
        "url": "https://docs.localstack.cloud",
    },
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
        "/_localstack/config": {
            "get": {
                "description": "Retrieve current LocalStack configuration",
                "responses": {
                    "200": {
                        "description": "Current LocalStack configuration",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "requestBody": {
                    "description": "Configuration option to update with new value",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "variable": {
                                        "type": "string",
                                        "pattern": "^[_a-zA-Z0-9]+$",
                                    },
                                    "value": {
                                        "type": ["number", "string"],
                                    },
                                },
                            }
                        }
                    },
                    "required": True,
                },
                "responses": {
                    "200": {
                        "description": "Configuration option is updated",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "variable": {"type": "string"},
                                        "value": {"type": ["number", "string"]},
                                    },
                                }
                            }
                        },
                    },
                    "400": {"description": "Bad request", "content": {"application/json": {}}},
                },
            },
        },
        "/_localstack/diagnose": {
            "get": {
                "description": "Retrieve diagnostics report",
                "responses": {
                    "200": {
                        "description": "Diagnostics report",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "version": {
                                            "type": "object",
                                            "properties": {
                                                "image-version": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "string"},
                                                        "sha256": {"type": "string"},
                                                        "tag": {"type": "string"},
                                                        "created": {"type": "string"},
                                                    },
                                                },
                                                "localstack-version": {
                                                    "type": "object",
                                                    "properties": {
                                                        "build-date": {"type": ["string", "null"]},
                                                        "build-git-hash": {
                                                            "type": ["string", "null"]
                                                        },
                                                        "build-version": {
                                                            "type": ["string", "null"]
                                                        },
                                                    },
                                                },
                                                "host": {
                                                    "type": "object",
                                                    "properties": {"kernel": {"type": "string"}},
                                                },
                                            },
                                        },
                                        "info": {
                                            "$ref": "#/components/schemas/Info",
                                        },
                                        "services": {"type": "object"},
                                        "config": {"type": "object"},
                                        "docker-inspect": {"type": "object"},
                                        "docker-dependent-image-hosts": {"type": "object"},
                                        "file-tree": {"type": "object"},
                                        "important-endpoints": {"type": "object"},
                                        "logs": {
                                            "type": "object",
                                            "properties": {
                                                "docker": {"type": "string"},
                                            },
                                        },
                                        "usage": {"type": "object"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/_localstack/health": {
            "get": {
                "description": "Retrieve available LocalStack features and AWS services",
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
                        "description": "Available LocalStack features and AWS services",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "edition": {
                                            "type": "string",
                                            "enum": ["community", "pro", "enterprise", "unknown"],
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
                        "description": "",
                        "content": {"text/plain": {}},
                    }
                }
            },
            "post": {
                "description": "Restart or terminate the LocalStack session",
                "responses": {
                    "200": {
                        "description": "Action was successful",
                        "content": {"text/plain": {}},
                    },
                    "400": {
                        "description": "Bad request",
                        "content": {"text/plain": {}},
                    },
                },
                "requestBody": {
                    "description": "Action to perform",
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
                "description": "Store arbitrary data to in-memory state",
                "responses": {
                    "200": {
                        "description": "Data was saved",
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
                    "description": "Data to save",
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
        "/_localstack/info": {
            "get": {
                "description": "Retrieve information about the current LocalStack session",
                "responses": {
                    "200": {
                        "description": "Information about the current LocalStack session",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Info"}}
                        },
                    }
                },
            }
        },
        "/_localstack/init": {
            "get": {
                "description": "Retrieve info about init scripts",
                "responses": {
                    "200": {
                        "description": "Info about init scripts",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/InitScripts",
                                }
                            }
                        },
                    }
                },
            },
        },
        "/_localstack/init/{stage}": {
            "get": {
                "description": "Retrieve info about init scripts in a specific stage",
                "parameters": [
                    {
                        "name": "stage",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Info about init scripts in a specific stage",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/InitScripts",
                                }
                            }
                        },
                    }
                },
            }
        },
        "/_localstack/plugins": {
            "get": {
                "description": "Retrieve info about plugins",
                "responses": {
                    "200": {
                        "description": "Info about plugins",
                        "content": {
                            # FIXME: This endpoint returns a JSON object whose keys are dynamic.
                            # This prevents it from being defined with JSON Schema.
                            "application/json": {}
                        },
                    }
                },
            }
        },
        "/_localstack/usage": {
            "get": {
                "description": "Retrieve usage info",
                "responses": {
                    "200": {
                        "description": "Usage info",
                        "content": {
                            "application/json": {},
                        },
                    }
                },
            }
        },
    },
    "components": {
        "schemas": {
            "Info": {
                "type": "object",
                "properties": {
                    "version": {"type": "string"},
                    "edition": {"type": "string"},
                    "is_license_activated": {"type": "boolean"},
                    "session_id": {"type": "string"},
                    "machine_id": {"type": "string"},
                    "system": {"type": "string"},
                    "is_docker": {"type": "boolean"},
                    "server_time_utc": {"type": "string"},
                    "uptime": {"type": "integer"},
                },
            },
            "InitScripts": {
                "type": "object",
                "properties": {
                    "completed": {
                        "type": "object",
                        "properties": {
                            "BOOT": {"type": "boolean"},
                            "START": {"type": "boolean"},
                            "READY": {"type": "boolean"},
                            "SHUTDOWN": {"type": "boolean"},
                        },
                    },
                    "scripts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "stage": {"type": "string"},
                                "name": {"type": "string"},
                                "state": {"type": "string"},
                            },
                        },
                    },
                },
            },
        }
    },
}
