"""AWS Ground Station service provider implementation.

This module implements the GroundStationProvider class that handles all Ground Station
API operations following LocalStack's ASF (AWS Service Framework) pattern.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import (
    ConfigIdResponse,
    ConfigTypeData,
    ContactIdResponse,
    DataflowEndpointGroupIdResponse,
    DependencyException,
    DescribeContactResponse,
    GetConfigResponse,
    GetDataflowEndpointGroupResponse,
    GetMinuteUsageResponse,
    GetMissionProfileResponse,
    GetSatelliteResponse,
    GroundstationApi,
    InvalidParameterException,
    ListConfigsResponse,
    ListContactsResponse,
    ListDataflowEndpointGroupsResponse,
    ListGroundStationsResponse,
    ListMissionProfilesResponse,
    ListSatellitesResponse,
    ListTagsForResourceResponse,
    MissionProfileIdResponse,
    ResourceNotFoundException,
    TagResourceResponse,
    UntagResourceResponse,
)
from localstack.services.plugins import ServiceLifecycleHook

from .models import (
    ConfigData,
    ConfigType,
    ContactData,
    ContactStatus,
    DataflowEndpointGroupData,
    MissionProfileData,
    groundstation_stores,
)
from .resource import (
    create_config_arn,
    create_contact_arn,
    create_dataflow_endpoint_group_arn,
    create_mission_profile_arn,
    parse_mission_profile_arn,
)
from .state_manager import start_contact_state_manager, stop_contact_state_manager
from .utils import (
    MOCK_GROUND_STATIONS,
    MOCK_SATELLITES,
    get_ground_station_by_name,
    get_satellite_by_id,
)
from .validation import (
    validate_contact_times,
    validate_dataflow_edge,
    validate_duration_range,
    validate_eirp,
    validate_endpoint_port,
    validate_frequency_range,
    validate_iam_role_arn,
    validate_security_group_ids,
    validate_tags,
)

LOG = logging.getLogger(__name__)


class GroundStationProvider(GroundstationApi, ServiceLifecycleHook):
    """AWS Ground Station service provider."""

    def on_after_init(self):
        """Called after the service is initialized. Start the contact state manager."""
        start_contact_state_manager()

    def on_before_stop(self):
        """Called before the service is stopped. Stop the contact state manager."""
        stop_contact_state_manager()

    # Configuration Management Operations
    def create_config(
        self,
        context: RequestContext,
        name: str,
        config_data: ConfigTypeData,
        tags: dict[str, str] | None = None,
    ) -> ConfigIdResponse:
        """Create a configuration."""
        store = groundstation_stores
        tags = tags or {}

        # Validate tags
        if tags:
            validate_tags(tags)

        # Determine config type from config_data
        config_type = None
        if "antennaDownlinkConfig" in config_data:
            config_type = ConfigType.ANTENNA_DOWNLINK
            # Validate frequency
            spectrum = config_data["antennaDownlinkConfig"]["spectrumConfig"]
            validate_frequency_range(
                spectrum["centerFrequency"]["value"], spectrum["centerFrequency"]["units"]
            )
        elif "antennaDownlinkDemodDecodeConfig" in config_data:
            config_type = ConfigType.ANTENNA_DOWNLINK_DEMOD_DECODE
            spectrum = config_data["antennaDownlinkDemodDecodeConfig"]["spectrumConfig"]
            validate_frequency_range(
                spectrum["centerFrequency"]["value"], spectrum["centerFrequency"]["units"]
            )
        elif "antennaUplinkConfig" in config_data:
            config_type = ConfigType.ANTENNA_UPLINK
            spectrum = config_data["antennaUplinkConfig"]["spectrumConfig"]
            validate_frequency_range(
                spectrum["centerFrequency"]["value"], spectrum["centerFrequency"]["units"]
            )
            # Validate EIRP
            if "targetEirp" in config_data["antennaUplinkConfig"]:
                validate_eirp(
                    config_data["antennaUplinkConfig"]["targetEirp"]["value"],
                    config_data["antennaUplinkConfig"]["targetEirp"]["units"],
                )
        elif "dataflowEndpointConfig" in config_data:
            config_type = ConfigType.DATAFLOW_ENDPOINT
        elif "trackingConfig" in config_data:
            config_type = ConfigType.TRACKING
        elif "uplinkEchoConfig" in config_data:
            config_type = ConfigType.UPLINK_ECHO
        else:
            raise InvalidParameterException("Invalid config data: unknown config type")

        # Generate UUID and ARN
        config_id = str(uuid.uuid4())
        config_arn = create_config_arn(
            context.region, context.account_id, config_type.value, config_id
        )

        # Create config data object
        config = ConfigData(
            config_id=config_id,
            config_arn=config_arn,
            config_type=config_type,
            name=name,
            config_data=config_data,
            tags=tags,
        )

        # Store config
        if config_id not in store.configs:
            store.configs[config_id] = {}
        store.configs[config_id] = config

        # Store tags
        if tags:
            store.tags[config_arn] = tags

        return ConfigIdResponse(
            configId=config_id,
            configArn=config_arn,
            configType=config_type.value,
        )

    def get_config(
        self,
        context: RequestContext,
        config_id: str,
        config_type: str,
    ) -> GetConfigResponse:
        """Get a configuration."""
        store = groundstation_stores

        if config_id not in store.configs:
            raise ResourceNotFoundException(f"Config {config_id} not found")

        config = store.configs[config_id]

        return GetConfigResponse(
            configId=config.config_id,
            configArn=config.config_arn,
            name=config.name,
            configType=config.config_type.value,
            configData=config.config_data,
            tags=config.tags,
        )

    def list_configs(
        self,
        context: RequestContext,
        max_results: int | None = None,
        next_token: str | None = None,
    ) -> ListConfigsResponse:
        """List configurations."""
        store = groundstation_stores

        configs_list = list(store.configs.values())
        config_list = [
            {
                "configId": c.config_id,
                "configArn": c.config_arn,
                "configType": c.config_type.value,
                "name": c.name,
            }
            for c in configs_list
        ]

        # Simple pagination
        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = config_list[start:end]

        result = {"configList": page}
        if end < len(config_list):
            result["nextToken"] = str(end)

        return ListConfigsResponse(**result)

    def update_config(
        self,
        context: RequestContext,
        config_id: str,
        name: str,
        config_type: str,
        config_data: ConfigTypeData,
    ) -> ConfigIdResponse:
        """Update a configuration."""
        store = groundstation_stores

        if config_id not in store.configs:
            raise ResourceNotFoundException(f"Config {config_id} not found")

        config = store.configs[config_id]
        config.name = name
        config.config_data = config_data
        config.updated_at = datetime.now(UTC)

        return ConfigIdResponse(
            configId=config.config_id,
            configArn=config.config_arn,
            configType=config.config_type.value,
        )

    def delete_config(
        self,
        context: RequestContext,
        config_id: str,
        config_type: str,
    ) -> ConfigIdResponse:
        """Delete a configuration."""
        store = groundstation_stores

        if config_id not in store.configs:
            raise ResourceNotFoundException(f"Config {config_id} not found")

        config = store.configs[config_id]

        # Check if config is used by any mission profile
        for mp in store.mission_profiles.values():
            if config.config_arn == mp.tracking_config_arn:
                raise DependencyException(
                    f"Config {config_id} is used by mission profile {mp.mission_profile_id}"
                )
            for edge in mp.dataflow_edges:
                if config.config_arn in edge:
                    raise DependencyException(
                        f"Config {config_id} is used by mission profile {mp.mission_profile_id}"
                    )

        config_arn = config.config_arn
        config_type_val = config.config_type.value

        del store.configs[config_id]
        if config_arn in store.tags:
            del store.tags[config_arn]

        return ConfigIdResponse(
            configId=config_id,
            configArn=config_arn,
            configType=config_type_val,
        )

    # Mission Profile Operations
    def create_mission_profile(
        self,
        context: RequestContext,
        name: str,
        contact_pre_pass_duration_seconds: int,
        contact_post_pass_duration_seconds: int,
        minimum_viable_contact_duration_seconds: int,
        dataflow_edges: list[list[str]],
        tracking_config_arn: str,
        tags: dict[str, str] | None = None,
        **kwargs,
    ) -> MissionProfileIdResponse:
        """Create a mission profile."""
        store = groundstation_stores
        tags = tags or {}

        # Validate tags
        if tags:
            validate_tags(tags)

        # Validate duration ranges
        validate_duration_range(
            contact_pre_pass_duration_seconds, 1, 7200, "contactPrePassDurationSeconds"
        )
        validate_duration_range(
            contact_post_pass_duration_seconds, 1, 7200, "contactPostPassDurationSeconds"
        )
        validate_duration_range(
            minimum_viable_contact_duration_seconds, 1, 21600, "minimumViableContactDurationSeconds"
        )

        # Validate dataflow edges
        for edge in dataflow_edges:
            if len(edge) == 2:
                validate_dataflow_edge(edge[0], edge[1], store)

        # Generate UUID and ARN
        mp_id = str(uuid.uuid4())
        mp_arn = create_mission_profile_arn(context.region, context.account_id, mp_id)

        # Create mission profile
        mp = MissionProfileData(
            mission_profile_id=mp_id,
            mission_profile_arn=mp_arn,
            name=name,
            contact_pre_pass_duration_seconds=contact_pre_pass_duration_seconds,
            contact_post_pass_duration_seconds=contact_post_pass_duration_seconds,
            minimum_viable_contact_duration_seconds=minimum_viable_contact_duration_seconds,
            dataflow_edges=dataflow_edges,
            tracking_config_arn=tracking_config_arn,
            tags=tags,
        )

        store.mission_profiles[mp_id] = mp

        if tags:
            store.tags[mp_arn] = tags

        return MissionProfileIdResponse(
            missionProfileId=mp_id,
            missionProfileArn=mp_arn,
        )

    def get_mission_profile(
        self,
        context: RequestContext,
        mission_profile_id: str,
    ) -> GetMissionProfileResponse:
        """Get a mission profile."""
        store = groundstation_stores

        if mission_profile_id not in store.mission_profiles:
            raise ResourceNotFoundException(f"Mission profile {mission_profile_id} not found")

        mp = store.mission_profiles[mission_profile_id]

        return GetMissionProfileResponse(
            missionProfileId=mp.mission_profile_id,
            missionProfileArn=mp.mission_profile_arn,
            name=mp.name,
            contactPrePassDurationSeconds=mp.contact_pre_pass_duration_seconds,
            contactPostPassDurationSeconds=mp.contact_post_pass_duration_seconds,
            minimumViableContactDurationSeconds=mp.minimum_viable_contact_duration_seconds,
            dataflowEdges=mp.dataflow_edges,
            trackingConfigArn=mp.tracking_config_arn,
            region=context.region,
            tags=mp.tags,
        )

    def list_mission_profiles(
        self,
        context: RequestContext,
        max_results: int | None = None,
        next_token: str | None = None,
    ) -> ListMissionProfilesResponse:
        """List mission profiles."""
        store = groundstation_stores

        mps = list(store.mission_profiles.values())
        mp_list = [
            {
                "missionProfileId": mp.mission_profile_id,
                "missionProfileArn": mp.mission_profile_arn,
                "name": mp.name,
                "region": context.region,
            }
            for mp in mps
        ]

        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = mp_list[start:end]

        result = {"missionProfileList": page}
        if end < len(mp_list):
            result["nextToken"] = str(end)

        return ListMissionProfilesResponse(**result)

    def update_mission_profile(
        self,
        context: RequestContext,
        mission_profile_id: str,
        name: str | None = None,
        contact_pre_pass_duration_seconds: int | None = None,
        contact_post_pass_duration_seconds: int | None = None,
        minimum_viable_contact_duration_seconds: int | None = None,
        dataflow_edges: list[list[str]] | None = None,
        tracking_config_arn: str | None = None,
        **kwargs,
    ) -> MissionProfileIdResponse:
        """Update a mission profile."""
        store = groundstation_stores

        if mission_profile_id not in store.mission_profiles:
            raise ResourceNotFoundException(f"Mission profile {mission_profile_id} not found")

        mp = store.mission_profiles[mission_profile_id]

        if name:
            mp.name = name
        if contact_pre_pass_duration_seconds is not None:
            mp.contact_pre_pass_duration_seconds = contact_pre_pass_duration_seconds
        if contact_post_pass_duration_seconds is not None:
            mp.contact_post_pass_duration_seconds = contact_post_pass_duration_seconds
        if minimum_viable_contact_duration_seconds is not None:
            mp.minimum_viable_contact_duration_seconds = minimum_viable_contact_duration_seconds
        if dataflow_edges is not None:
            mp.dataflow_edges = dataflow_edges
        if tracking_config_arn:
            mp.tracking_config_arn = tracking_config_arn

        mp.updated_at = datetime.now(UTC)

        return MissionProfileIdResponse(
            missionProfileId=mp.mission_profile_id,
        )

    def delete_mission_profile(
        self,
        context: RequestContext,
        mission_profile_id: str,
    ) -> MissionProfileIdResponse:
        """Delete a mission profile."""
        store = groundstation_stores

        if mission_profile_id not in store.mission_profiles:
            raise ResourceNotFoundException(f"Mission profile {mission_profile_id} not found")

        mp = store.mission_profiles[mission_profile_id]

        # Check if used by any contacts
        for contact in store.contacts.values():
            if contact.mission_profile_arn == mp.mission_profile_arn:
                if contact.contact_status in [
                    ContactStatus.SCHEDULING,
                    ContactStatus.SCHEDULED,
                    ContactStatus.PASS,
                ]:
                    raise DependencyException(
                        f"Mission profile {mission_profile_id} has active contacts"
                    )

        mp_arn = mp.mission_profile_arn
        del store.mission_profiles[mission_profile_id]

        if mp_arn in store.tags:
            del store.tags[mp_arn]

        return MissionProfileIdResponse(
            missionProfileId=mission_profile_id,
        )

    # Contact Operations
    def reserve_contact(
        self,
        context: RequestContext,
        mission_profile_arn: str,
        satellite_arn: str,
        start_time: datetime,
        end_time: datetime,
        ground_station: str,
        tags: dict[str, str] | None = None,
        **kwargs,
    ) -> ContactIdResponse:
        """Reserve a contact."""
        store = groundstation_stores
        tags = tags or {}

        if tags:
            validate_tags(tags)

        # Validate mission profile exists
        mp_info = parse_mission_profile_arn(mission_profile_arn)
        mp_id = mp_info["mission_profile_id"]
        if mp_id not in store.mission_profiles:
            raise ResourceNotFoundException(f"Mission profile {mission_profile_arn} not found")

        mp = store.mission_profiles[mp_id]

        # Validate satellite exists
        sat_id = satellite_arn.split("/")[-1]
        get_satellite_by_id(sat_id)

        # Validate ground station exists
        get_ground_station_by_name(ground_station)

        # Validate contact times
        validate_contact_times(start_time, end_time, mp.minimum_viable_contact_duration_seconds)

        # Generate UUID and ARN
        contact_id = str(uuid.uuid4())
        contact_arn = create_contact_arn(context.region, context.account_id, contact_id)

        # Calculate pre/post pass times
        pre_pass_start = start_time - timedelta(seconds=mp.contact_pre_pass_duration_seconds)
        post_pass_end = end_time + timedelta(seconds=mp.contact_post_pass_duration_seconds)

        # Create contact
        contact = ContactData(
            contact_id=contact_id,
            contact_arn=contact_arn,
            ground_station=ground_station,
            mission_profile_arn=mission_profile_arn,
            satellite_arn=satellite_arn,
            start_time=start_time,
            end_time=end_time,
            contact_status=ContactStatus.SCHEDULED,  # Immediately scheduled
            pre_pass_start_time=pre_pass_start,
            post_pass_end_time=post_pass_end,
            region=context.region,
            tags=tags,
        )

        store.contacts[contact_id] = contact

        if tags:
            store.tags[contact_arn] = tags

        return ContactIdResponse(contactId=contact_id)

    def describe_contact(
        self,
        context: RequestContext,
        contact_id: str,
    ) -> DescribeContactResponse:
        """Describe a contact."""
        store = groundstation_stores

        if contact_id not in store.contacts:
            raise ResourceNotFoundException(f"Contact {contact_id} not found")

        contact = store.contacts[contact_id]

        # Update contact status based on current time (simplified state machine)
        now = datetime.now(UTC)
        # Make times timezone-aware if they aren't already
        start_time = (
            contact.start_time.replace(tzinfo=UTC)
            if contact.start_time.tzinfo is None
            else contact.start_time
        )
        end_time = (
            contact.end_time.replace(tzinfo=UTC)
            if contact.end_time.tzinfo is None
            else contact.end_time
        )

        if contact.contact_status == ContactStatus.SCHEDULED:
            if now >= start_time and now < end_time:
                contact.contact_status = ContactStatus.PASS
            elif now >= end_time:
                contact.contact_status = ContactStatus.COMPLETED
        elif contact.contact_status == ContactStatus.PASS:
            if now >= end_time:
                contact.contact_status = ContactStatus.COMPLETED

        return DescribeContactResponse(
            contactId=contact.contact_id,
            contactStatus=contact.contact_status.value,
            startTime=contact.start_time,
            endTime=contact.end_time,
            groundStation=contact.ground_station,
            missionProfileArn=contact.mission_profile_arn,
            satelliteArn=contact.satellite_arn,
            region=contact.region,
            contactArn=contact.contact_arn,
            tags=contact.tags,
        )

    def list_contacts(
        self,
        context: RequestContext,
        status_list: list[str],
        start_time: datetime,
        end_time: datetime,
        ground_station: str | None = None,
        satellite_arn: str | None = None,
        max_results: int | None = None,
        next_token: str | None = None,
        **kwargs,
    ) -> ListContactsResponse:
        """List contacts."""
        store = groundstation_stores

        # Make filter times timezone-aware if they aren't already
        filter_start_time = (
            start_time.replace(tzinfo=UTC) if start_time.tzinfo is None else start_time
        )
        filter_end_time = end_time.replace(tzinfo=UTC) if end_time.tzinfo is None else end_time

        # Filter contacts
        contacts_list = []
        for contact in store.contacts.values():
            # Update status first
            now = datetime.now(UTC)
            # Make times timezone-aware if they aren't already
            contact_start = (
                contact.start_time.replace(tzinfo=UTC)
                if contact.start_time.tzinfo is None
                else contact.start_time
            )
            contact_end = (
                contact.end_time.replace(tzinfo=UTC)
                if contact.end_time.tzinfo is None
                else contact.end_time
            )

            if contact.contact_status == ContactStatus.SCHEDULED:
                if now >= contact_start and now < contact_end:
                    contact.contact_status = ContactStatus.PASS
                elif now >= contact_end:
                    contact.contact_status = ContactStatus.COMPLETED
            elif contact.contact_status == ContactStatus.PASS:
                if now >= contact_end:
                    contact.contact_status = ContactStatus.COMPLETED

            # Apply filters
            if contact.contact_status.value not in status_list:
                continue
            if contact_start < filter_start_time or contact_end > filter_end_time:
                continue
            if ground_station and contact.ground_station != ground_station:
                continue
            if satellite_arn and contact.satellite_arn != satellite_arn:
                continue

            contacts_list.append(
                {
                    "contactId": contact.contact_id,
                    "contactStatus": contact.contact_status.value,
                    "startTime": contact.start_time,
                    "endTime": contact.end_time,
                    "groundStation": contact.ground_station,
                    "missionProfileArn": contact.mission_profile_arn,
                    "satelliteArn": contact.satellite_arn,
                    "region": contact.region,
                }
            )

        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = contacts_list[start:end]

        result = {"contactList": page}
        if end < len(contacts_list):
            result["nextToken"] = str(end)

        return ListContactsResponse(**result)

    def cancel_contact(
        self,
        context: RequestContext,
        contact_id: str,
    ) -> ContactIdResponse:
        """Cancel a contact."""
        store = groundstation_stores

        if contact_id not in store.contacts:
            raise ResourceNotFoundException(f"Contact {contact_id} not found")

        contact = store.contacts[contact_id]

        # Can only cancel if not completed/failed/already cancelled
        if contact.contact_status in [
            ContactStatus.COMPLETED,
            ContactStatus.FAILED,
            ContactStatus.CANCELLED,
        ]:
            raise InvalidParameterException(
                f"Cannot cancel contact in {contact.contact_status.value} state"
            )

        contact.contact_status = ContactStatus.CANCELLED
        contact.updated_at = datetime.now(UTC)

        return ContactIdResponse(contactId=contact_id)

    # Dataflow Endpoint Group Operations
    def create_dataflow_endpoint_group(
        self,
        context: RequestContext,
        endpoint_details: list[dict],
        tags: dict[str, str] | None = None,
        **kwargs,
    ) -> DataflowEndpointGroupIdResponse:
        """Create a dataflow endpoint group."""
        store = groundstation_stores
        tags = tags or {}

        if tags:
            validate_tags(tags)

        # Validate endpoints and security details
        for endpoint in endpoint_details:
            if "endpoint" in endpoint and "address" in endpoint["endpoint"]:
                port = endpoint["endpoint"]["address"].get("port")
                if port:
                    validate_endpoint_port(port)

            # Validate IAM role and security groups if provided
            if "securityDetails" in endpoint:
                security_details = endpoint["securityDetails"]

                if "roleArn" in security_details:
                    validate_iam_role_arn(security_details["roleArn"])

                if "securityGroupIds" in security_details:
                    validate_security_group_ids(security_details["securityGroupIds"])

        # Generate UUID and ARN
        deg_id = str(uuid.uuid4())
        deg_arn = create_dataflow_endpoint_group_arn(context.region, context.account_id, deg_id)

        # Create endpoint group
        deg = DataflowEndpointGroupData(
            dataflow_endpoint_group_id=deg_id,
            dataflow_endpoint_group_arn=deg_arn,
            endpoints=endpoint_details,  # Store as-is
            tags=tags,
        )

        store.dataflow_endpoint_groups[deg_id] = deg

        if tags:
            store.tags[deg_arn] = tags

        return DataflowEndpointGroupIdResponse(
            dataflowEndpointGroupId=deg_id,
            dataflowEndpointGroupArn=deg_arn,
        )

    def get_dataflow_endpoint_group(
        self,
        context: RequestContext,
        dataflow_endpoint_group_id: str,
    ) -> GetDataflowEndpointGroupResponse:
        """Get a dataflow endpoint group."""
        store = groundstation_stores

        if dataflow_endpoint_group_id not in store.dataflow_endpoint_groups:
            raise ResourceNotFoundException(
                f"Dataflow endpoint group {dataflow_endpoint_group_id} not found"
            )

        deg = store.dataflow_endpoint_groups[dataflow_endpoint_group_id]

        return GetDataflowEndpointGroupResponse(
            dataflowEndpointGroupId=deg.dataflow_endpoint_group_id,
            dataflowEndpointGroupArn=deg.dataflow_endpoint_group_arn,
            endpointsDetails=deg.endpoints,
            tags=deg.tags,
        )

    def list_dataflow_endpoint_groups(
        self,
        context: RequestContext,
        max_results: int | None = None,
        next_token: str | None = None,
    ) -> ListDataflowEndpointGroupsResponse:
        """List dataflow endpoint groups."""
        store = groundstation_stores

        degs = list(store.dataflow_endpoint_groups.values())
        deg_list = [
            {
                "dataflowEndpointGroupId": deg.dataflow_endpoint_group_id,
                "dataflowEndpointGroupArn": deg.dataflow_endpoint_group_arn,
            }
            for deg in degs
        ]

        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = deg_list[start:end]

        result = {"dataflowEndpointGroupList": page}
        if end < len(deg_list):
            result["nextToken"] = str(end)

        return ListDataflowEndpointGroupsResponse(**result)

    def delete_dataflow_endpoint_group(
        self,
        context: RequestContext,
        dataflow_endpoint_group_id: str,
    ) -> DataflowEndpointGroupIdResponse:
        """Delete a dataflow endpoint group."""
        store = groundstation_stores

        if dataflow_endpoint_group_id not in store.dataflow_endpoint_groups:
            raise ResourceNotFoundException(
                f"Dataflow endpoint group {dataflow_endpoint_group_id} not found"
            )

        deg = store.dataflow_endpoint_groups[dataflow_endpoint_group_id]

        # Check if used by mission profiles or contacts
        for mp in store.mission_profiles.values():
            for edge in mp.dataflow_edges:
                for config_arn in edge:
                    # Check if config references this endpoint group
                    pass  # Simplified check

        deg_id = deg.dataflow_endpoint_group_id
        deg_arn = deg.dataflow_endpoint_group_arn

        del store.dataflow_endpoint_groups[dataflow_endpoint_group_id]

        if deg_arn in store.tags:
            del store.tags[deg_arn]

        return DataflowEndpointGroupIdResponse(
            dataflowEndpointGroupId=deg_id,
        )

    # Satellite Operations (Read-only)
    def get_satellite(
        self,
        context: RequestContext,
        satellite_id: str,
    ) -> GetSatelliteResponse:
        """Get satellite information."""
        satellite = get_satellite_by_id(satellite_id)

        return GetSatelliteResponse(
            satelliteId=satellite.satellite_id,
            satelliteArn=satellite.satellite_arn,
            noradSatelliteID=satellite.norad_satellite_id,
            groundStations=satellite.ground_stations,
        )

    def list_satellites(
        self,
        context: RequestContext,
        max_results: int | None = None,
        next_token: str | None = None,
    ) -> ListSatellitesResponse:
        """List satellites."""
        satellites = [
            {
                "satelliteId": s.satellite_id,
                "satelliteArn": s.satellite_arn,
                "noradSatelliteID": s.norad_satellite_id,
                "groundStations": s.ground_stations,
            }
            for s in MOCK_SATELLITES
        ]

        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = satellites[start:end]

        result = {"satellites": page}
        if end < len(satellites):
            result["nextToken"] = str(end)

        return ListSatellitesResponse(**result)

    # Ground Station Operations (Read-only)
    def list_ground_stations(
        self,
        context: RequestContext,
        satellite_id: str | None = None,
        max_results: int | None = None,
        next_token: str | None = None,
    ) -> ListGroundStationsResponse:
        """List ground stations."""
        ground_stations = MOCK_GROUND_STATIONS

        # Filter by satellite if provided
        if satellite_id:
            satellite = get_satellite_by_id(satellite_id)
            ground_stations = [
                gs for gs in ground_stations if gs.ground_station_name in satellite.ground_stations
            ]

        gs_list = [
            {
                "groundStationId": gs.ground_station_id,
                "groundStationName": gs.ground_station_name,
                "region": gs.region,
            }
            for gs in ground_stations
        ]

        max_results = max_results or 100
        start = int(next_token) if next_token else 0
        end = start + max_results
        page = gs_list[start:end]

        result = {"groundStationList": page}
        if end < len(gs_list):
            result["nextToken"] = str(end)

        return ListGroundStationsResponse(**result)

    # Usage Tracking
    def get_minute_usage(
        self,
        context: RequestContext,
        month: int,
        year: int,
    ) -> GetMinuteUsageResponse:
        """Get minute usage for a month."""
        store = groundstation_stores

        if month < 1 or month > 12:
            raise InvalidParameterException(f"Month must be between 1 and 12 (got {month})")

        # Calculate usage from contacts
        total_minutes = 0
        upcoming_minutes = 0

        for contact in store.contacts.values():
            # Check if contact is in the requested month/year
            if contact.start_time.year == year and contact.start_time.month == month:
                duration_minutes = (contact.end_time - contact.start_time).total_seconds() / 60
                # Add pre/post pass durations
                if contact.pre_pass_start_time:
                    duration_minutes += (
                        contact.start_time - contact.pre_pass_start_time
                    ).total_seconds() / 60
                if contact.post_pass_end_time:
                    duration_minutes += (
                        contact.post_pass_end_time - contact.end_time
                    ).total_seconds() / 60

                total_minutes += duration_minutes

                # Check if upcoming
                if contact.contact_status in [ContactStatus.SCHEDULING, ContactStatus.SCHEDULED]:
                    upcoming_minutes += duration_minutes

        return GetMinuteUsageResponse(
            estimatedMinutesRemaining=1000000,  # Mock unlimited
            totalScheduledMinutes=int(total_minutes),
            upcomingMinutesScheduled=int(upcoming_minutes),
        )

    # Tagging Operations
    def tag_resource(
        self,
        context: RequestContext,
        resource_arn: str,
        tags: dict[str, str],
    ) -> TagResourceResponse:
        """Tag a resource."""
        store = groundstation_stores

        validate_tags(tags)

        # Check if resource exists
        resource_found = False
        for config in store.configs.values():
            if config.config_arn == resource_arn:
                config.tags.update(tags)
                resource_found = True
                break

        if not resource_found:
            for mp in store.mission_profiles.values():
                if mp.mission_profile_arn == resource_arn:
                    mp.tags.update(tags)
                    resource_found = True
                    break

        if not resource_found:
            for contact in store.contacts.values():
                if contact.contact_arn == resource_arn:
                    contact.tags.update(tags)
                    resource_found = True
                    break

        if not resource_found:
            for deg in store.dataflow_endpoint_groups.values():
                if deg.dataflow_endpoint_group_arn == resource_arn:
                    deg.tags.update(tags)
                    resource_found = True
                    break

        if not resource_found:
            raise ResourceNotFoundException(f"Resource {resource_arn} not found")

        # Update tags store
        if resource_arn not in store.tags:
            store.tags[resource_arn] = {}
        store.tags[resource_arn].update(tags)

        return TagResourceResponse()

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: str,
        tag_keys: list[str],
    ) -> UntagResourceResponse:
        """Untag a resource."""
        store = groundstation_stores

        # Check if resource exists and remove tags
        resource_found = False
        for config in store.configs.values():
            if config.config_arn == resource_arn:
                for key in tag_keys:
                    config.tags.pop(key, None)
                resource_found = True
                break

        if not resource_found:
            for mp in store.mission_profiles.values():
                if mp.mission_profile_arn == resource_arn:
                    for key in tag_keys:
                        mp.tags.pop(key, None)
                    resource_found = True
                    break

        if not resource_found:
            for contact in store.contacts.values():
                if contact.contact_arn == resource_arn:
                    for key in tag_keys:
                        contact.tags.pop(key, None)
                    resource_found = True
                    break

        if not resource_found:
            for deg in store.dataflow_endpoint_groups.values():
                if deg.dataflow_endpoint_group_arn == resource_arn:
                    for key in tag_keys:
                        deg.tags.pop(key, None)
                    resource_found = True
                    break

        if not resource_found:
            raise ResourceNotFoundException(f"Resource {resource_arn} not found")

        # Update tags store
        if resource_arn in store.tags:
            for key in tag_keys:
                store.tags[resource_arn].pop(key, None)

        return UntagResourceResponse()

    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: str,
    ) -> ListTagsForResourceResponse:
        """List tags for a resource."""
        store = groundstation_stores

        tags = {}

        # Find resource and get tags
        for config in store.configs.values():
            if config.config_arn == resource_arn:
                tags = config.tags
                break

        if not tags:
            for mp in store.mission_profiles.values():
                if mp.mission_profile_arn == resource_arn:
                    tags = mp.tags
                    break

        if not tags:
            for contact in store.contacts.values():
                if contact.contact_arn == resource_arn:
                    tags = contact.tags
                    break

        if not tags:
            for deg in store.dataflow_endpoint_groups.values():
                if deg.dataflow_endpoint_group_arn == resource_arn:
                    tags = deg.tags
                    break

        # If still not found, check tags store
        if not tags and resource_arn in store.tags:
            tags = store.tags[resource_arn]

        if not tags and resource_arn not in [c.config_arn for c in store.configs.values()]:
            # Only raise if resource truly doesn't exist
            all_arns = (
                [c.config_arn for c in store.configs.values()]
                + [mp.mission_profile_arn for mp in store.mission_profiles.values()]
                + [c.contact_arn for c in store.contacts.values()]
                + [
                    deg.dataflow_endpoint_group_arn
                    for deg in store.dataflow_endpoint_groups.values()
                ]
            )
            if resource_arn not in all_arns:
                raise ResourceNotFoundException(f"Resource {resource_arn} not found")

        return ListTagsForResourceResponse(tags=tags or {})
