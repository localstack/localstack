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
            "name": "LocalStack Support",
            "url": "https://www.localstack.cloud/contact",
            "email": "info@localstack.cloud",
        },
        "version": __version__,
    },
    "externalDocs": {
        "description": "LocalStack Documentation",
        "url": "https://docs.localstack.cloud",
    },
    "components": {
        "schemas": {
            "SessionInfo": {
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
        },
        "parameters": {
            "SesMessageId": {
                "name": "id",
                "description": "ID of the message (`id` field of SES message)",
                "in": "query",
                "required": False,
                "schema": {
                    "type": "string",
                },
            },
            "SnsAccountId": {
                "name": "accountId",
                "description": "`accountId` field of the platform endpoint message",
                "in": "query",
                "schema": {
                    "type": "string",
                    "default": "000000000000",
                },
                "required": False,
            },
            "SnsRegion": {
                "name": "region",
                "description": "`region` field of the platform endpoint message",
                "in": "query",
                "schema": {
                    "type": "string",
                    "default": "us-east-1",
                },
                "required": False,
            },
            "SnsEndpointArn": {
                "name": "endpointArn",
                "description": "`endpointArn` field of the platform endpoint message",
                "in": "query",
                "schema": {
                    "type": "string",
                },
                "required": False,
            },
        },
    },
    "paths": {
        #
        # Service endpoints. Mind the sorting
        #
        "/_aws/cloudwatch/metrics/raw": {},
        "/_aws/dynamodb/expired": {
            "delete": {
                "description": "Delete expired items from DynamoDB tables with TTL enabled",
                "responses": {
                    "200": {
                        "description": "Operation was successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "ExpiredItems": {
                                            "description": "Number of expired items that were deleted",
                                            "type": "integer",
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/_aws/lambda/runtimes": {},
        "/_aws/ses": {
            "get": {
                "description": "Retrieve sent messages",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SesMessageId",
                    },
                    {
                        "name": "email",
                        "description": "Source of the message (`source` field of SES message)",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                        },
                    },
                ],
                "responses": {
                    "200": {
                        "description": "List of sent messages",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "messages": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "Id": {
                                                        "type": "string",
                                                    },
                                                    "Region": {
                                                        "type": "string",
                                                    },
                                                    "Timestamp": {
                                                        "type": "string",
                                                    },
                                                    "Destination": {
                                                        "type": "string",
                                                    },
                                                    "RawData": {
                                                        "type": "string",
                                                    },
                                                    "Source": {
                                                        "type": "string",
                                                    },
                                                    "Subject": {
                                                        "type": "string",
                                                    },
                                                    "Template": {
                                                        "type": "string",
                                                    },
                                                    "TemplateData": {
                                                        "type": "string",
                                                    },
                                                    "Body": {
                                                        "type": "object",
                                                        "properties": {
                                                            "html_part": {
                                                                "type": "string",
                                                            },
                                                            "text_part": {
                                                                "type": "string",
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
            },
            "delete": {
                "description": "Discard a message",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SesMessageId",
                    }
                ],
                "responses": {
                    "204": {
                        "description": "Message was successfully discarded",
                    }
                },
            },
        },
        "/_aws/sns/platform-endpoint-messages": {
            "get": {
                "description": "Retrieve platform endpoint messages",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SnsAccountId",
                    },
                    {
                        "$ref": "#/components/parameters/SnsRegion",
                    },
                    {
                        "$ref": "#/components/parameters/SnsEndpointArn",
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Platform endpoint messages",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "platform_endpoint_messages": {
                                            "type": "object",
                                        },
                                        "region": {
                                            "type": "string",
                                        },
                                    },
                                }
                            }
                        },
                    }
                },
            },
            "delete": {
                "description": "Discard a platform endpoint message",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SnsAccountId",
                    },
                    {
                        "$ref": "#/components/parameters/SnsRegion",
                    },
                    {
                        "$ref": "#/components/parameters/SnsEndpointArn",
                    },
                ],
                "responses": {
                    "204": {
                        "description": "Platform endpoint message was discarded",
                    }
                },
            },
        },
        "/_aws/sns/sms-messages": {},
        "/_aws/sns/subscription-tokens": {},
        "/_aws/sqs/messages": {},
        #
        # Framework endpoints. Mind the sorting
        #
        "/_localstack/config": {
            "get": {
                "description": "Get current LocalStack configuration",
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
                "description": "Get diagnostics report",
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
                                            "$ref": "#/components/schemas/SessionInfo",
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
                "description": "Get available LocalStack features and AWS services",
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
                "description": "Restart or terminate LocalStack session",
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
                "description": "Get information about the current LocalStack session",
                "responses": {
                    "200": {
                        "description": "Information about the current LocalStack session",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SessionInfo"}
                            }
                        },
                    }
                },
            }
        },
        "/_localstack/init": {
            "get": {
                "description": "Get information about init scripts",
                "responses": {
                    "200": {
                        "description": "Information about init scripts",
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
                "description": "Get information about init scripts in a specific stage",
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
                        "description": "Information about init scripts in a specific stage",
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
                "description": "Get plugin information",
                "responses": {
                    "200": {
                        "description": "Plugin information",
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
                "description": "Get usage information",
                "responses": {
                    "200": {
                        "description": "Usage information",
                        "content": {
                            "application/json": {},
                        },
                    }
                },
            }
        },
    },
}
