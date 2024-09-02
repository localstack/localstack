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
        "/_localstack/config": {
            "get": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                }
                            }
                        },
                    }
                }
            },
            "post": {
                "requestBody": {
                    "description": "Config option to update with new value",
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
                        "description": "Config option was updated",
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
                "responses": {
                    "200": {
                        "description": "",  # TODO
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
                                        "services": {"type": "object"},  # TODO add full schema
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
                }
            }
        },
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
        "/_localstack/info": {
            "get": {
                "responses": {
                    "200": {
                        "description": "Information about the current LocalStack session",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Info"}}
                        },
                    }
                }
            }
        },
        "/_localstack/init": {
            "get": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/InitScripts",
                                }
                            }
                        },
                    }
                }
            },
        },
        "/_localstack/init/{stage}": {
            "get": {
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
                        "description": "",  # TODO
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
        "/_localstack/usage": {
            "get": {
                "responses": {
                    "200": {
                        "description": "",  # TODO
                        "content": {
                            "application/json": {},
                        },
                    }
                }
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
