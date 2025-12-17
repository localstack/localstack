"""
TypedDict models for LocalStack internal endpoints.

These models define the response types for internal APIs like health, info, diagnose, etc.
They are used to auto-generate OpenAPI schemas.
"""

from typing import Literal, NotRequired, TypedDict


class HealthActionRequest(TypedDict):
    """Request body for POST /_localstack/health."""

    action: Literal["restart", "kill"]


class HealthServices(TypedDict):
    """Service health states."""

    # Dynamic keys - service names map to their state strings


class HealthResponse(TypedDict):
    """Response from the health endpoint."""

    services: dict[str, str]
    edition: str
    version: str
    # May contain additional dynamic state fields


class InfoResponse(TypedDict):
    """Response from the info endpoint."""

    version: str
    edition: str
    is_license_activated: bool
    session_id: str
    machine_id: str
    system: str
    is_docker: bool
    server_time_utc: str
    uptime: int


class DiagnoseVersion(TypedDict):
    """Version information in diagnose response."""

    image_version: NotRequired[dict]
    localstack_version: NotRequired[dict]
    host: NotRequired[dict]


class DiagnoseResponse(TypedDict):
    """Response from the diagnose endpoint."""

    version: NotRequired[DiagnoseVersion]
    info: NotRequired[InfoResponse]
    services: NotRequired[dict]
    config: NotRequired[dict]


class PluginDetails(TypedDict):
    """Details about a single plugin."""

    name: str
    is_initialized: bool
    is_loaded: bool
    requires_license: NotRequired[bool]


class PluginsResponse(TypedDict):
    """Response from the plugins endpoint."""

    # Dynamic keys - namespace names map to lists of plugin details


class InitScriptInfo(TypedDict):
    """Information about a single init script."""

    stage: str
    name: str
    state: str


class InitScriptsResponse(TypedDict):
    """Response from the init scripts endpoint."""

    completed: dict[str, bool]
    scripts: list[InitScriptInfo]


class ConfigUpdateRequest(TypedDict):
    """Request to update a config variable."""

    variable: str
    value: str | int | float | bool


class ConfigUpdateResponse(TypedDict):
    """Response from config update."""

    variable: str
    value: str | int | float | bool | None
