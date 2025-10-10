"""Input validation for Ground Station service.

This module provides validation functions for:
- Frequency ranges (S-band, X-band, Ka-band)
- Dataflow edge type sequences
- Contact time validation
- Parameter ranges and constraints
- IAM role ARN validation
- Config data validation (enum values, required fields)
"""

import re
from datetime import UTC, datetime
from typing import Any

from localstack.aws.api.groundstation import InvalidParameterException


def validate_frequency_range(frequency: float, units: str) -> None:
    """Validate frequency is within allowed band ranges.

    Valid bands:
    - S-band: 2-4 GHz
    - X-band: 8-12 GHz
    - Ka-band: 26-40 GHz

    Args:
        frequency: Frequency value
        units: Frequency units (MHz or GHz)

    Raises:
        InvalidParameterException: If frequency is outside valid ranges
    """
    # Convert to MHz for consistent validation
    freq_mhz = frequency if units == "MHz" else frequency * 1000

    # Valid ranges in MHz
    valid_ranges = [
        (2000, 4000),  # S-band
        (8000, 12000),  # X-band
        (26000, 40000),  # Ka-band
    ]

    for min_freq, max_freq in valid_ranges:
        if min_freq <= freq_mhz <= max_freq:
            return

    raise InvalidParameterException(
        f"Frequency {frequency} {units} is outside valid ranges (S-band: 2-4 GHz, X-band: 8-12 GHz, Ka-band: 26-40 GHz)"
    )


def validate_eirp(eirp: float, units: str = "dBW") -> None:
    """Validate EIRP is within allowed range.

    Args:
        eirp: EIRP value
        units: EIRP units (dBW)

    Raises:
        InvalidParameterException: If EIRP is outside valid range
    """
    # Typical EIRP range: -10 to 50 dBW
    if not (-10 <= eirp <= 50):
        raise InvalidParameterException(
            f"EIRP {eirp} {units} is outside valid range (-10 to 50 dBW)"
        )


def validate_dataflow_edge(source_arn: str, dest_arn: str, store) -> None:
    """Validate dataflow edge type sequence.

    Valid transitions:
    - tracking -> antenna-downlink
    - tracking -> antenna-downlink-demod-decode
    - tracking -> antenna-uplink
    - antenna-downlink -> dataflow-endpoint
    - antenna-downlink-demod-decode -> dataflow-endpoint
    - antenna-uplink -> dataflow-endpoint
    - antenna-uplink -> uplink-echo
    - uplink-echo -> dataflow-endpoint

    Args:
        source_arn: Source config ARN
        dest_arn: Destination config ARN
        store: GroundStationStore to lookup configs

    Raises:
        InvalidParameterException: If config type sequence is invalid
    """
    from .resource import parse_config_arn

    # Parse ARNs to get config types
    try:
        source_info = parse_config_arn(source_arn)
        dest_info = parse_config_arn(dest_arn)
    except ValueError as e:
        raise InvalidParameterException(str(e))

    source_type = source_info["config_type"]
    dest_type = dest_info["config_type"]

    # Valid transitions
    valid_transitions = {
        "tracking": ["antenna-downlink", "antenna-downlink-demod-decode", "antenna-uplink"],
        "antenna-downlink": ["dataflow-endpoint"],
        "antenna-downlink-demod-decode": ["dataflow-endpoint"],
        "antenna-uplink": ["dataflow-endpoint", "uplink-echo"],
        "uplink-echo": ["dataflow-endpoint"],
    }

    if source_type not in valid_transitions:
        raise InvalidParameterException(
            f"Config type '{source_type}' cannot be used as dataflow edge source"
        )

    if dest_type not in valid_transitions[source_type]:
        raise InvalidParameterException(
            f"Invalid dataflow edge: '{source_type}' -> '{dest_type}'. "
            f"Valid destinations for '{source_type}': {', '.join(valid_transitions[source_type])}"
        )


def validate_contact_times(
    start_time: datetime, end_time: datetime, minimum_duration: int = 60
) -> None:
    """Validate contact time parameters.

    Rules:
    - end_time > start_time
    - start_time > now (must be in future)
    - (end_time - start_time) >= minimum_duration

    Args:
        start_time: Contact start time
        end_time: Contact end time
        minimum_duration: Minimum contact duration in seconds

    Raises:
        InvalidParameterException: If time parameters are invalid
    """
    now = datetime.now(UTC)

    # Make times timezone-aware if they aren't already
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC)
    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=UTC)

    if start_time <= now:
        raise InvalidParameterException(
            f"Contact start time must be in the future. Start: {start_time}, Now: {now}"
        )

    if end_time <= start_time:
        raise InvalidParameterException(
            f"Contact end time must be after start time. Start: {start_time}, End: {end_time}"
        )

    duration = (end_time - start_time).total_seconds()
    if duration < minimum_duration:
        raise InvalidParameterException(
            f"Contact duration {duration}s is less than minimum {minimum_duration}s"
        )


def validate_duration_range(
    seconds: int, min_val: int, max_val: int, param_name: str = "duration"
) -> None:
    """Validate duration is within allowed range.

    Args:
        seconds: Duration in seconds
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        param_name: Parameter name for error message

    Raises:
        InvalidParameterException: If duration is outside range
    """
    if seconds < min_val or seconds > max_val:
        raise InvalidParameterException(
            f"{param_name} must be between {min_val} and {max_val} seconds (got {seconds})"
        )


def validate_endpoint_port(port: int) -> None:
    """Validate endpoint port number.

    Args:
        port: Port number

    Raises:
        InvalidParameterException: If port is invalid
    """
    if not (1 <= port <= 65535):
        raise InvalidParameterException(f"Port must be between 1 and 65535 (got {port})")


def validate_tags(tags: dict) -> None:
    """Validate tags dictionary.

    Rules:
    - Maximum 50 tags
    - Key: 1-128 characters
    - Value: 0-256 characters
    - Key cannot be empty

    Args:
        tags: Tags dictionary

    Raises:
        InvalidParameterException: If tags are invalid
    """
    if len(tags) > 50:
        raise InvalidParameterException(f"Cannot have more than 50 tags (got {len(tags)})")

    for key, value in tags.items():
        if not key or len(key) == 0:
            raise InvalidParameterException("Tag key cannot be empty")

        if len(key) > 128:
            raise InvalidParameterException(
                f"Tag key cannot exceed 128 characters (got {len(key)})"
            )

        if len(value) > 256:
            raise InvalidParameterException(
                f"Tag value cannot exceed 256 characters (got {len(value)})"
            )


def validate_iam_role_arn(role_arn: str) -> None:
    """Validate IAM role ARN format.

    Args:
        role_arn: IAM role ARN string

    Raises:
        InvalidParameterException: If ARN format is invalid
    """
    # Basic ARN format: arn:partition:iam::account-id:role/role-name
    arn_pattern = r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$"

    if not re.match(arn_pattern, role_arn):
        raise InvalidParameterException(
            f"Invalid IAM role ARN format: {role_arn}. "
            "Expected format: arn:aws:iam::ACCOUNT:role/ROLENAME"
        )


def validate_security_group_ids(security_group_ids: list[str]) -> None:
    """Validate security group ID format.

    Args:
        security_group_ids: List of security group IDs

    Raises:
        InvalidParameterException: If security group ID format is invalid
    """
    sg_pattern = r"^sg-[a-f0-9]{8,17}$"

    for sg_id in security_group_ids:
        if not re.match(sg_pattern, sg_id):
            raise InvalidParameterException(
                f"Invalid security group ID format: {sg_id}. Expected format: sg-XXXXXXXX"
            )


def validate_config_data(config_data: dict[str, Any]) -> None:
    """Validate config data structure and enum values.

    Args:
        config_data: Configuration data dictionary

    Raises:
        InvalidParameterException: If enum values are invalid or required fields are missing
    """
    # Tracking config validation
    if "trackingConfig" in config_data:
        tracking = config_data["trackingConfig"]
        if "autotrack" in tracking:
            valid_autotrack = ["REQUIRED", "PREFERRED", "REMOVED"]
            if tracking["autotrack"] not in valid_autotrack:
                raise InvalidParameterException(
                    f"Invalid autotrack value: {tracking['autotrack']}. "
                    f"Must be one of: {', '.join(valid_autotrack)}"
                )

    # Antenna uplink config validation
    if "antennaUplinkConfig" in config_data:
        uplink = config_data["antennaUplinkConfig"]
        if "spectrumConfig" in uplink:
            spectrum = uplink["spectrumConfig"]
            if "polarization" in spectrum:
                valid_polarization = ["LEFT_HAND", "RIGHT_HAND", "NONE"]
                if spectrum["polarization"] not in valid_polarization:
                    raise InvalidParameterException(
                        f"Invalid polarization value: {spectrum['polarization']}. "
                        f"Must be one of: {', '.join(valid_polarization)}"
                    )

    # Dataflow endpoint config validation
    if "dataflowEndpointConfig" in config_data:
        dataflow = config_data["dataflowEndpointConfig"]
        if "dataflowEndpointRegion" in dataflow:
            # Valid AWS regions
            valid_regions = [
                "us-east-1",
                "us-east-2",
                "us-west-1",
                "us-west-2",
                "eu-west-1",
                "eu-central-1",
                "eu-north-1",
                "ap-southeast-1",
                "ap-southeast-2",
                "ap-northeast-1",
                "ap-northeast-2",
                "sa-east-1",
                "af-south-1",
                "me-south-1",
            ]
            if dataflow["dataflowEndpointRegion"] not in valid_regions:
                raise InvalidParameterException(
                    f"Invalid region: {dataflow['dataflowEndpointRegion']}. "
                    "Must be a valid AWS region."
                )
