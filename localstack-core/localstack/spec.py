"""
API specifications and schema.
"""

from typing import Final

from localstack.version import __version__

# OpenAPI specification for the public REST API

#
# Note:
# - The schema definitions must be closed. Make sure `required` and `additionalProperties` are used.
# - Mind the sorting.
#

OPENAPI: Final = {
    "openapi": "3.1.0",
    "info": {
        "title": "LocalStack REST API for Community",
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
    "servers": [{"url": "http://localhost.localstack.cloud:4566"}],
    "components": {
        "schemas": {
            "SessionInfo": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "version",
                    "edition",
                    "is_license_activated",
                    "session_id",
                    "machine_id",
                    "system",
                    "is_docker",
                    "server_time_utc",
                    "uptime",
                ],
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
                "additionalProperties": False,
                "required": ["completed", "scripts"],
                "properties": {
                    "completed": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["BOOT", "START", "READY", "SHUTDOWN"],
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
                            "additionalProperties": False,
                            "required": ["stage", "name", "state"],
                            "properties": {
                                "stage": {"type": "string"},
                                "name": {"type": "string"},
                                "state": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "SnsSubscriptionTokenError": {
                "type": "object",
                "additionalProperties": False,
                "required": ["error", "subscription_arn"],
                "properties": {
                    "error": {
                        "type": "string",
                    },
                    "subscription_arn": {
                        "type": "string",
                    },
                },
            },
            "SesSentEmail": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "Id",
                    "Region",
                    "Timestamp",
                    "Destination",
                    "RawData",
                    "Source",
                    "Subject",
                    "Template",
                    "TemplateData",
                    "Body",
                ],
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
                        "additionalProperties": False,
                        "required": ["html_part", "text_part"],
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
                "description": "`accountId` field of the resource",
                "in": "query",
                "required": False,
                "schema": {
                    "type": "string",
                    "default": "000000000000",
                },
            },
            "SnsRegion": {
                "name": "region",
                "description": "`region` field of the resource",
                "in": "query",
                "required": False,
                "schema": {
                    "type": "string",
                    "default": "us-east-1",
                },
            },
            "SnsEndpointArn": {
                "name": "endpointArn",
                "description": "`endpointArn` field of the resource",
                "in": "query",
                "required": False,
                "schema": {
                    "type": "string",
                },
            },
            "SnsPhoneNumber": {
                "name": "phoneNumber",
                "description": "`phoneNumber` field of the resource",
                "in": "query",
                "required": False,
                "schema": {
                    "type": "string",
                },
            },
        },
    },
    "paths": {
        #
        # Provider endpoints
        #
        "/_aws/cloudwatch/metrics/raw": {
            "get": {
                "description": "Retrieve CloudWatch metrics",
                "responses": {
                    "200": {
                        "description": "CloudWatch metrics",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["metrics"],
                                    "properties": {
                                        "metrics": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "additionalProperties": False,
                                                "required": [
                                                    "ns",
                                                    "n",
                                                    "v",
                                                    "t",
                                                    "d",
                                                    "account",
                                                    "region",
                                                ],
                                                "properties": {
                                                    "ns": {
                                                        "type": "string",
                                                        "description": "Namespace",
                                                    },
                                                    "n": {
                                                        "type": "string",
                                                        "description": "Metric name",
                                                    },
                                                    "v": {
                                                        "type": "string",
                                                        "description": "Metric value",
                                                    },
                                                    "t": {
                                                        "type": "number",
                                                        "description": "Timestamp",
                                                    },
                                                    "d": {
                                                        "type": "array",
                                                        "description": "Dimensions",
                                                        "items": {
                                                            "type": "object",
                                                            "additionalProperties": False,
                                                            "required": ["n", "v"],
                                                            "properties": {
                                                                "n": {
                                                                    "type": "string",
                                                                    "description": "Dimension name",
                                                                },
                                                                "v": {
                                                                    "type": "string",
                                                                    "description": "Dimension value",
                                                                },
                                                            },
                                                        },
                                                    },
                                                    "account": {
                                                        "type": "string",
                                                        "description": "Account ID",
                                                    },
                                                    "region": {
                                                        "type": "string",
                                                        "description": "Region name",
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
            }
        },
        "/_aws/dynamodb/expired": {
            "delete": {
                "description": "Delete expired items from TTL-enabled DynamoDB tables",
                "responses": {
                    "200": {
                        "description": "Operation was successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["ExpiredItems"],
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
        "/_aws/events/rules/{rule_arn}/trigger": {
            "get": {
                "description": "Trigger a scheduled EventBridge rule",
                "parameters": [
                    {
                        "name": "rule_arn",
                        "description": "EventBridge rule ARN",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    },
                ],
                "responses": {
                    "200": {
                        "description": "EventBridge rule was triggered",
                    },
                    "404": {
                        "description": "Not found",
                    },
                },
            }
        },
        "/_aws/lambda/init": {
            "get": {
                "description": "Retrieve Lambda runtime init binary",
                "responses": {
                    "200": {
                        "description": "Lambda runtime init binary",
                        "content": {
                            "application/octet-stream": {},
                        },
                    }
                },
            },
        },
        "/_aws/lambda/runtimes": {
            "get": {
                "description": "List available Lambda runtimes",
                "parameters": [
                    {
                        "name": "filter",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                            "default": "supported",
                            "enum": ["all", "deprecated", "supported"],
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Available Lambda runtimes",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["Runtimes"],
                                    "properties": {
                                        "Runtimes": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                            },
                                        }
                                    },
                                },
                            },
                        },
                    }
                },
            }
        },
        "/_aws/ses": {
            "get": {
                "description": "Retrieve sent SES messages",
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
                                    "additionalProperties": False,
                                    "required": ["messages"],
                                    "properties": {
                                        "messages": {
                                            "type": "array",
                                            "items": {
                                                "$ref": "#/components/schemas/SesSentEmail",
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
                "description": "Discard sent SES messages",
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
                "description": "Retrieve SNS platform endpoint messages",
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
                                    "additionalProperties": False,
                                    "required": ["platform_endpoint_messages", "region"],
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
                "description": "Discard SNS platform endpoint messages",
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
        "/_aws/sns/sms-messages": {
            "get": {
                "description": "Retrieve SNS SMS messages",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SnsAccountId",
                    },
                    {
                        "$ref": "#/components/parameters/SnsRegion",
                    },
                    {
                        "$ref": "#/components/parameters/SnsPhoneNumber",
                    },
                ],
                "responses": {
                    "200": {
                        "description": "SNS SMS messages",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["sms_messages", "region"],
                                    "properties": {
                                        "sms_messages": {"type": "object"},
                                        "region": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            },
            "delete": {
                "description": "Discard SNS SMS messages",
                "parameters": [
                    {
                        "$ref": "#/components/parameters/SnsAccountId",
                    },
                    {
                        "$ref": "#/components/parameters/SnsRegion",
                    },
                    {
                        "$ref": "#/components/parameters/SnsPhoneNumber",
                    },
                ],
                "responses": {
                    "204": {
                        "description": "SMS message was discarded",
                        "content": {"text/plain": {}},
                    }
                },
            },
        },
        "/_aws/sns/subscription-tokens/{subscription_arn}": {
            "get": {
                "description": "Retrieve SNS subscription token for confirmation",
                "parameters": [
                    {
                        "name": "subscription_arn",
                        "description": "`subscriptionArn` resource of subscription token",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Subscription token",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["subscription_token", "subscription_arn"],
                                    "properties": {
                                        "subscription_token": {
                                            "type": "string",
                                        },
                                        "subscription_arn": {
                                            "type": "string",
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "400": {
                        "description": "Bad request",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/SnsSubscriptionTokenError",
                                }
                            }
                        },
                    },
                    "404": {
                        "description": "Not found",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/SnsSubscriptionTokenError",
                                }
                            }
                        },
                    },
                },
            },
        },
        "/_aws/sqs/messages": {
            "get": {
                "description": "List SQS queue messages without side effects",
                "parameters": [
                    {
                        "name": "QueueUrl",
                        "description": "SQS queue URL",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                        },
                    }
                ],
                "responses": {
                    "200": {
                        "description": "SQS queue messages",
                        "content": {
                            "text/xml": {},
                        },
                    },
                    "400": {
                        "description": "Bad request",
                        "content": {
                            "text/xml": {},
                        },
                    },
                    "404": {
                        "description": "Not found",
                        "content": {
                            "text/xml": {},
                        },
                    },
                },
            },
        },
        "/_aws/sqs/messages/{region}/{account_id}/{queue_name}": {
            "get": {
                "description": "List SQS messages without side effects",
                "parameters": [
                    {
                        "name": "region",
                        "description": "SQS queue region",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    },
                    {
                        "name": "account_id",
                        "description": "SQS queue account ID",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    },
                    {
                        "name": "queue_name",
                        "description": "SQS queue name",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string",
                        },
                    },
                ],
                "responses": {
                    "200": {
                        "description": "SQS queue messages",
                        "content": {
                            "text/xml": {},
                        },
                    },
                    "400": {
                        "description": "Bad request",
                        "content": {
                            "text/xml": {},
                        },
                    },
                    "404": {
                        "description": "Not found",
                        "content": {
                            "text/xml": {},
                        },
                    },
                },
            },
        },
        #
        # Framework endpoints
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
                                "additionalProperties": False,
                                "required": ["variable", "value"],
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
                                    "additionalProperties": False,
                                    "required": ["variable", "value"],
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
                                    "additionalProperties": False,
                                    "required": [
                                        "version",
                                        "info",
                                        "services",
                                        "config",
                                        "docker-inspect",
                                        "docker-dependent-image-hosts",
                                        "file-tree",
                                        "important-endpoints",
                                        "logs",
                                        "usage",
                                    ],
                                    "properties": {
                                        "version": {
                                            "type": "object",
                                            "additionalProperties": False,
                                            "required": [
                                                "image-version",
                                                "localstack-version",
                                                "host",
                                            ],
                                            "properties": {
                                                "image-version": {
                                                    "type": "object",
                                                    "additionalProperties": False,
                                                    "required": ["id", "sha256", "tag", "created"],
                                                    "properties": {
                                                        "id": {"type": "string"},
                                                        "sha256": {"type": "string"},
                                                        "tag": {"type": "string"},
                                                        "created": {"type": "string"},
                                                    },
                                                },
                                                "localstack-version": {
                                                    "type": "object",
                                                    "additionalProperties": False,
                                                    "required": [
                                                        "build-date",
                                                        "build-git-hash",
                                                        "build-version",
                                                    ],
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
                                                    "additionalProperties": False,
                                                    "required": ["kernel"],
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
                                            "additionalProperties": False,
                                            "required": ["docker"],
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
                                    "additionalProperties": False,
                                    "required": ["edition", "features", "services", "version"],
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
                                "additionalProperties": False,
                                "required": ["action"],
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
                                    "additionalProperties": False,
                                    "required": ["status"],
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
                "description": "",
                "responses": {
                    "200": {
                        "description": "",
                        "content": {"application/json": {}},
                    }
                },
            }
        },
        "/_localstack/usage": {
            "get": {
                "description": "",
                "responses": {
                    "200": {
                        "description": "",
                        "content": {
                            "application/json": {},
                        },
                    }
                },
            }
        },
    },
}
