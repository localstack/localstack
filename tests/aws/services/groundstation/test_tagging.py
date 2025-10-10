"""Integration tests for Ground Station tagging operations.

Tests tagging, untagging, and listing tags for all resource types.
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


@markers.aws.validated
class TestConfigTagging:
    """Test tagging operations for Config resources."""

    def test_tag_config(self, aws_client):
        """Test tagging a config resource."""
        # Create config
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-tag-config", configData=config_data
        )
        config_arn = config_response["configArn"]

        # Tag config
        aws_client.groundstation.tag_resource(
            resourceArn=config_arn, tags={"Environment": "Test", "Owner": "TeamA"}
        )

        # List tags
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)

        assert tags_response["tags"]["Environment"] == "Test"
        assert tags_response["tags"]["Owner"] == "TeamA"

    def test_untag_config(self, aws_client):
        """Test untagging a config resource."""
        # Create config with tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-untag-config",
            configData=config_data,
            tags={"Environment": "Test", "Owner": "TeamA", "Project": "Satellite"},
        )
        config_arn = config_response["configArn"]

        # Untag specific keys
        aws_client.groundstation.untag_resource(
            resourceArn=config_arn, tagKeys=["Owner", "Project"]
        )

        # Verify remaining tags
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)

        assert "Environment" in tags_response["tags"]
        assert "Owner" not in tags_response["tags"]
        assert "Project" not in tags_response["tags"]

    def test_update_config_tags(self, aws_client):
        """Test updating tags (overwriting existing values)."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-update-tags",
            configData=config_data,
            tags={"Environment": "Dev"},
        )
        config_arn = config_response["configArn"]

        # Update tag value
        aws_client.groundstation.tag_resource(
            resourceArn=config_arn, tags={"Environment": "Production"}
        )

        # Verify updated value
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)

        assert tags_response["tags"]["Environment"] == "Production"


@markers.aws.validated
class TestMissionProfileTagging:
    """Test tagging operations for Mission Profile resources."""

    def test_tag_mission_profile(self, aws_client):
        """Test tagging a mission profile resource."""
        # Create mission profile
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-mp-tagging",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="test-tag-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )
        mp_arn = mp_response["missionProfileArn"]

        # Tag mission profile
        aws_client.groundstation.tag_resource(
            resourceArn=mp_arn, tags={"Mission": "TestSat", "Priority": "High"}
        )

        # List tags
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=mp_arn)

        assert tags_response["tags"]["Mission"] == "TestSat"
        assert tags_response["tags"]["Priority"] == "High"

    def test_untag_mission_profile(self, aws_client):
        """Test untagging a mission profile resource."""
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-mp-untagging",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="test-untag-mp",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
            tags={"Mission": "TestSat", "Priority": "High"},
        )
        mp_arn = mp_response["missionProfileArn"]

        # Untag
        aws_client.groundstation.untag_resource(resourceArn=mp_arn, tagKeys=["Priority"])

        # Verify
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=mp_arn)

        assert "Mission" in tags_response["tags"]
        assert "Priority" not in tags_response["tags"]


@markers.aws.validated
class TestContactTagging:
    """Test tagging operations for Contact resources."""

    def test_tag_contact(self, aws_client):
        """Test tagging a contact resource."""
        from datetime import datetime, timedelta

        # Create and reserve contact
        tracking_config = aws_client.groundstation.create_config(
            name="tracking-for-contact-tagging",
            configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        )
        mp_response = aws_client.groundstation.create_mission_profile(
            name="mp-for-contact-tagging",
            contactPrePassDurationSeconds=120,
            contactPostPassDurationSeconds=120,
            minimumViableContactDurationSeconds=60,
            dataflowEdges=[],
            trackingConfigArn=tracking_config["configArn"],
        )

        start_time = datetime.utcnow() + timedelta(hours=1)
        end_time = start_time + timedelta(minutes=10)

        reserve_response = aws_client.groundstation.reserve_contact(
            missionProfileArn=mp_response["missionProfileArn"],
            satelliteArn="arn:aws:groundstation:us-east-1:000000000000:satellite/25544",
            startTime=start_time,
            endTime=end_time,
            groundStation="Ohio Ground Station",
        )
        contact_id = reserve_response["contactId"]

        # Get contact ARN
        contact_response = aws_client.groundstation.describe_contact(contactId=contact_id)
        contact_arn = contact_response["contactArn"]

        # Tag contact
        aws_client.groundstation.tag_resource(
            resourceArn=contact_arn, tags={"ContactType": "Downlink"}
        )

        # Verify
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=contact_arn)

        assert tags_response["tags"]["ContactType"] == "Downlink"


@markers.aws.validated
class TestDataflowEndpointGroupTagging:
    """Test tagging operations for Dataflow Endpoint Group resources."""

    def test_tag_dataflow_endpoint_group(self, aws_client):
        """Test tagging a dataflow endpoint group resource."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "test-endpoint",
                }
            }
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details
        )
        deg_arn = deg_response["dataflowEndpointGroupArn"]

        # Tag dataflow endpoint group
        aws_client.groundstation.tag_resource(
            resourceArn=deg_arn, tags={"Network": "Private", "Region": "US-East"}
        )

        # Verify
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=deg_arn)

        assert tags_response["tags"]["Network"] == "Private"
        assert tags_response["tags"]["Region"] == "US-East"

    def test_untag_dataflow_endpoint_group(self, aws_client):
        """Test untagging a dataflow endpoint group resource."""
        endpoint_details = [
            {
                "endpoint": {
                    "address": {"name": "10.0.1.100", "port": 50000},
                    "name": "test-untag",
                }
            }
        ]

        deg_response = aws_client.groundstation.create_dataflow_endpoint_group(
            endpointDetails=endpoint_details,
            tags={"Network": "Private", "Region": "US-East"},
        )
        deg_arn = deg_response["dataflowEndpointGroupArn"]

        # Untag
        aws_client.groundstation.untag_resource(resourceArn=deg_arn, tagKeys=["Region"])

        # Verify
        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=deg_arn)

        assert "Network" in tags_response["tags"]
        assert "Region" not in tags_response["tags"]


@markers.aws.validated
class TestTaggingErrors:
    """Test error cases for tagging operations."""

    def test_tag_invalid_resource(self, aws_client):
        """Test tagging a non-existent resource."""
        invalid_arn = "arn:aws:groundstation:us-east-1:123456789012:config/tracking/00000000-0000-0000-0000-000000000000"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(resourceArn=invalid_arn, tags={"Test": "Value"})
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_list_tags_invalid_resource(self, aws_client):
        """Test listing tags for a non-existent resource."""
        invalid_arn = "arn:aws:groundstation:us-east-1:123456789012:config/tracking/00000000-0000-0000-0000-000000000000"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.list_tags_for_resource(resourceArn=invalid_arn)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_untag_invalid_resource(self, aws_client):
        """Test untagging a non-existent resource."""
        invalid_arn = "arn:aws:groundstation:us-east-1:123456789012:config/tracking/00000000-0000-0000-0000-000000000000"

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.untag_resource(resourceArn=invalid_arn, tagKeys=["Test"])
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"

    def test_tag_with_too_many_tags(self, aws_client):
        """Test tagging with more than 50 tags (AWS limit)."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-too-many-tags", configData=config_data
        )
        config_arn = config_response["configArn"]

        # Create 51 tags (exceeds limit of 50)
        too_many_tags = {f"Key{i}": f"Value{i}" for i in range(51)}

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(resourceArn=config_arn, tags=too_many_tags)
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_tag_with_empty_key(self, aws_client):
        """Test tagging with empty key."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-empty-key", configData=config_data
        )
        config_arn = config_response["configArn"]

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(resourceArn=config_arn, tags={"": "value"})
        assert exc.value.response["Error"]["Code"] == "ValidationException"

    def test_tag_with_invalid_key_length(self, aws_client):
        """Test tagging with key longer than 128 characters."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-long-key", configData=config_data
        )
        config_arn = config_response["configArn"]

        long_key = "a" * 129  # Exceeds 128 character limit

        with pytest.raises(ClientError) as exc:
            aws_client.groundstation.tag_resource(resourceArn=config_arn, tags={long_key: "value"})
        assert exc.value.response["Error"]["Code"] == "ValidationException"


@markers.aws.validated
class TestListTagsForResource:
    """Test ListTagsForResource operation."""

    def test_list_tags_empty(self, aws_client):
        """Test listing tags for a resource with no tags."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_response = aws_client.groundstation.create_config(
            name="test-no-tags", configData=config_data
        )
        config_arn = config_response["configArn"]

        tags_response = aws_client.groundstation.list_tags_for_resource(resourceArn=config_arn)

        assert "tags" in tags_response
        assert tags_response["tags"] == {}

    def test_list_tags_multiple_resources(self, aws_client):
        """Test that tags are isolated per resource."""
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}

        config1_response = aws_client.groundstation.create_config(
            name="test-tags-1", configData=config_data, tags={"Resource": "Config1"}
        )
        config2_response = aws_client.groundstation.create_config(
            name="test-tags-2", configData=config_data, tags={"Resource": "Config2"}
        )

        tags1 = aws_client.groundstation.list_tags_for_resource(
            resourceArn=config1_response["configArn"]
        )
        tags2 = aws_client.groundstation.list_tags_for_resource(
            resourceArn=config2_response["configArn"]
        )

        assert tags1["tags"]["Resource"] == "Config1"
        assert tags2["tags"]["Resource"] == "Config2"
