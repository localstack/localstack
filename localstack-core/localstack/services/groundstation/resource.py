"""ARN generation and resource utilities for Ground Station service.

This module provides:
- ARN generation functions for all resource types
- ARN parsing functions for validation and extraction
- Resource validation utilities
"""


def create_config_arn(region: str, account: str, config_type: str, config_id: str) -> str:
    """Create a config ARN.

    Format: arn:aws:groundstation:{region}:{account}:config/{config-type}/{config-id}

    Args:
        region: AWS region
        account: AWS account ID
        config_type: Configuration type
        config_id: Configuration UUID

    Returns:
        Config ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:config/{config_type}/{config_id}"


def create_mission_profile_arn(region: str, account: str, mission_profile_id: str) -> str:
    """Create a mission profile ARN.

    Format: arn:aws:groundstation:{region}:{account}:mission-profile/{mission-profile-id}

    Args:
        region: AWS region
        account: AWS account ID
        mission_profile_id: Mission profile UUID

    Returns:
        Mission profile ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:mission-profile/{mission_profile_id}"


def create_contact_arn(region: str, account: str, contact_id: str) -> str:
    """Create a contact ARN.

    Format: arn:aws:groundstation:{region}:{account}:contact/{contact-id}

    Args:
        region: AWS region
        account: AWS account ID
        contact_id: Contact UUID

    Returns:
        Contact ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:contact/{contact_id}"


def create_dataflow_endpoint_group_arn(region: str, account: str, group_id: str) -> str:
    """Create a dataflow endpoint group ARN.

    Format: arn:aws:groundstation:{region}:{account}:dataflow-endpoint-group/{group-id}

    Args:
        region: AWS region
        account: AWS account ID
        group_id: Endpoint group UUID

    Returns:
        Dataflow endpoint group ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:dataflow-endpoint-group/{group_id}"


def create_satellite_arn(region: str, account: str, satellite_id: str) -> str:
    """Create a satellite ARN.

    Format: arn:aws:groundstation:{region}:{account}:satellite/{satellite-id}

    Args:
        region: AWS region
        account: AWS account ID
        satellite_id: Satellite ID (NORAD ID)

    Returns:
        Satellite ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:satellite/{satellite_id}"


def create_ground_station_arn(region: str, account: str, ground_station_id: str) -> str:
    """Create a ground station ARN.

    Format: arn:aws:groundstation:{region}:{account}:ground-station/{ground-station-id}

    Args:
        region: AWS region
        account: AWS account ID
        ground_station_id: Ground station ID

    Returns:
        Ground station ARN string
    """
    # TODO: Implement in T024
    return f"arn:aws:groundstation:{region}:{account}:ground-station/{ground_station_id}"


def parse_config_arn(arn: str) -> dict[str, str]:
    """Parse a config ARN.

    Args:
        arn: Config ARN string

    Returns:
        Dict with region, account, config_type, config_id

    Raises:
        InvalidParameterException: If ARN format is invalid
    """
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[1] != "aws" or parts[2] != "groundstation":
        raise ValueError(f"Invalid config ARN format: {arn}")

    region = parts[3]
    account = parts[4]
    resource_parts = parts[5].split("/")

    if len(resource_parts) < 3 or resource_parts[0] != "config":
        raise ValueError(f"Invalid config ARN format: {arn}")

    return {
        "region": region,
        "account": account,
        "config_type": resource_parts[1],
        "config_id": resource_parts[2],
    }


def parse_mission_profile_arn(arn: str) -> dict[str, str]:
    """Parse a mission profile ARN.

    Args:
        arn: Mission profile ARN string

    Returns:
        Dict with region, account, mission_profile_id

    Raises:
        InvalidParameterException: If ARN format is invalid
    """
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[1] != "aws" or parts[2] != "groundstation":
        raise ValueError(f"Invalid mission profile ARN format: {arn}")

    region = parts[3]
    account = parts[4]
    resource_parts = parts[5].split("/")

    if len(resource_parts) < 2 or resource_parts[0] != "mission-profile":
        raise ValueError(f"Invalid mission profile ARN format: {arn}")

    return {
        "region": region,
        "account": account,
        "mission_profile_id": resource_parts[1],
    }


def parse_contact_arn(arn: str) -> dict[str, str]:
    """Parse a contact ARN.

    Args:
        arn: Contact ARN string

    Returns:
        Dict with region, account, contact_id

    Raises:
        InvalidParameterException: If ARN format is invalid
    """
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[1] != "aws" or parts[2] != "groundstation":
        raise ValueError(f"Invalid contact ARN format: {arn}")

    region = parts[3]
    account = parts[4]
    resource_parts = parts[5].split("/")

    if len(resource_parts) < 2 or resource_parts[0] != "contact":
        raise ValueError(f"Invalid contact ARN format: {arn}")

    return {
        "region": region,
        "account": account,
        "contact_id": resource_parts[1],
    }
