"""Data models and state management for AWS Ground Station service.

This module defines:
- Data classes for all Ground Station entities
- GroundStationStore for multi-account/multi-region state management
- ContactStateManager for background timer-based state transitions
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from localstack.services.stores import BaseStore, LocalAttribute


class ConfigType(str, Enum):
    """Configuration type enumeration."""

    ANTENNA_DOWNLINK = "antenna-downlink"
    ANTENNA_DOWNLINK_DEMOD_DECODE = "antenna-downlink-demod-decode"
    ANTENNA_UPLINK = "antenna-uplink"
    DATAFLOW_ENDPOINT = "dataflow-endpoint"
    TRACKING = "tracking"
    UPLINK_ECHO = "uplink-echo"


class ContactStatus(str, Enum):
    """Contact status enumeration for state machine."""

    SCHEDULING = "SCHEDULING"
    SCHEDULED = "SCHEDULED"
    PASS = "PASS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class ConfigData:
    """Configuration data model."""

    config_id: str  # UUID v4
    config_arn: str  # arn:aws:groundstation:region:account:config/type/id
    config_type: ConfigType
    name: str
    config_data: dict[str, Any]  # Type-specific configuration
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MissionProfileData:
    """Mission profile data model."""

    mission_profile_id: str  # UUID v4
    mission_profile_arn: str
    name: str
    minimum_viable_contact_duration_seconds: int
    contact_pre_pass_duration_seconds: int
    contact_post_pass_duration_seconds: int
    dataflow_edges: list[list[str]]  # Ordered config ARN pairs
    tracking_config_arn: str | None = None
    streams_kms_key_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ContactData:
    """Contact data model with state machine."""

    contact_id: str  # UUID v4
    contact_arn: str
    ground_station: str
    mission_profile_arn: str
    satellite_arn: str
    start_time: datetime
    end_time: datetime
    contact_status: ContactStatus
    contact_name: str | None = None
    error_message: str | None = None
    maximum_elevation: float | None = None
    pre_pass_start_time: datetime | None = None
    post_pass_end_time: datetime | None = None
    region: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EndpointAddress:
    """Endpoint address (IP and port)."""

    name: str  # IP address or hostname
    port: int  # 1-65535


@dataclass
class DataflowEndpointData:
    """Dataflow endpoint data."""

    name: str
    address: EndpointAddress
    mtu: int | None = None


@dataclass
class DataflowEndpointGroupData:
    """Dataflow endpoint group data model."""

    dataflow_endpoint_group_id: str  # UUID v4
    dataflow_endpoint_group_arn: str
    endpoints: list[DataflowEndpointData]
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SatelliteData:
    """Satellite data (read-only mock catalog)."""

    satellite_id: str  # NORAD ID
    satellite_arn: str
    satellite_name: str
    norad_satellite_id: int
    ground_stations: list[str]


@dataclass
class GroundStationData:
    """Ground station data (read-only mock catalog)."""

    ground_station_id: str
    ground_station_arn: str
    ground_station_name: str
    region: str


class GroundStationStore(BaseStore):
    """Ground Station service state storage.

    All collections use AccountRegionBundle for multi-account/region isolation.
    Supports Cloud Pods persistence automatically.
    """

    # Resource collections (LocalAttribute provides account/region isolation automatically)
    configs: dict[str, ConfigData] = LocalAttribute(default=dict)
    mission_profiles: dict[str, MissionProfileData] = LocalAttribute(default=dict)
    contacts: dict[str, ContactData] = LocalAttribute(default=dict)
    dataflow_endpoint_groups: dict[str, DataflowEndpointGroupData] = LocalAttribute(default=dict)

    # Tags collection (resource ARN → tags dict)
    tags: dict[str, dict[str, str]] = LocalAttribute(default=dict)


# Global store instance
groundstation_stores = GroundStationStore()


class ContactStateManager:
    """Background timer for automatic contact state transitions.

    Manages contact state machine:
    - SCHEDULING → SCHEDULED (on successful reservation)
    - SCHEDULED → PASS (when current_time >= start_time)
    - PASS → COMPLETED (when current_time >= end_time)

    Runs as background thread checking every 5 seconds.
    """

    def __init__(self, store: GroundStationStore):
        """Initialize contact state manager.

        Args:
            store: GroundStationStore instance
        """
        self.store = store
        self.running = False
        self.thread = None
        # TODO: Implement background thread in T039

    def start(self):
        """Start the background state transition thread."""
        # TODO: Implement in T039
        pass

    def stop(self):
        """Stop the background state transition thread."""
        # TODO: Implement in T039
        pass

    def _check_contacts(self):
        """Check all contacts and update states based on current time."""
        # TODO: Implement in T039
        pass
