"""Unit tests for Ground Station validation logic."""

import pytest

from localstack.aws.api.groundstation import InvalidParameterException
from localstack.services.groundstation.validation import (
    validate_duration_range,
    validate_eirp,
    validate_frequency_range,
    validate_tags,
)


class TestFrequencyValidation:
    """Tests for frequency range validation."""

    @pytest.mark.parametrize(
        "frequency,units",
        [
            (2200.0, "MHz"),  # S-band
            (2000.0, "MHz"),  # S-band lower bound
            (4000.0, "MHz"),  # S-band upper bound
            (8400.0, "MHz"),  # X-band
            (8000.0, "MHz"),  # X-band lower bound
            (12000.0, "MHz"),  # X-band upper bound
            (30.0, "GHz"),  # Ka-band (30000 MHz)
            (26.0, "GHz"),  # Ka-band lower bound
            (40.0, "GHz"),  # Ka-band upper bound
        ],
    )
    def test_valid_frequencies(self, frequency, units):
        """Test that valid frequencies pass validation."""
        # Should not raise
        validate_frequency_range(frequency, units)

    @pytest.mark.parametrize(
        "frequency,units",
        [
            (1000.0, "MHz"),  # Too low
            (1999.0, "MHz"),  # Just below S-band
            (4001.0, "MHz"),  # Just above S-band, below X-band
            (7999.0, "MHz"),  # Just below X-band
            (12001.0, "MHz"),  # Just above X-band, below Ka-band
            (25.0, "GHz"),  # Just below Ka-band
            (41.0, "GHz"),  # Just above Ka-band
            (100.0, "GHz"),  # Way too high
        ],
    )
    def test_invalid_frequencies(self, frequency, units):
        """Test that invalid frequencies are rejected."""
        with pytest.raises(InvalidParameterException) as exc:
            validate_frequency_range(frequency, units)

        assert "Frequency" in str(exc.value)
        assert "outside valid ranges" in str(exc.value)

    def test_frequency_validation_ghz_conversion(self):
        """Test that GHz values are correctly converted to MHz."""
        # 2.2 GHz = 2200 MHz (S-band)
        validate_frequency_range(2.2, "GHz")  # Should pass

        # 1.0 GHz = 1000 MHz (invalid)
        with pytest.raises(InvalidParameterException):
            validate_frequency_range(1.0, "GHz")


class TestEIRPValidation:
    """Tests for EIRP validation."""

    @pytest.mark.parametrize(
        "eirp",
        [
            -10.0,  # Minimum valid
            0.0,  # Mid-range
            30.0,  # Common value
            50.0,  # Maximum valid
        ],
    )
    def test_valid_eirp(self, eirp):
        """Test that valid EIRP values pass validation."""
        # Should not raise
        validate_eirp(eirp, "dBW")

    @pytest.mark.parametrize(
        "eirp",
        [
            -11.0,  # Just below minimum
            -50.0,  # Way too low
            51.0,  # Just above maximum
            100.0,  # Way too high
        ],
    )
    def test_invalid_eirp(self, eirp):
        """Test that invalid EIRP values are rejected."""
        with pytest.raises(InvalidParameterException) as exc:
            validate_eirp(eirp, "dBW")

        assert "EIRP" in str(exc.value)
        assert "outside valid range" in str(exc.value)


class TestDurationValidation:
    """Tests for duration range validation."""

    def test_valid_contact_pre_pass_duration(self):
        """Test valid contact pre-pass duration."""
        validate_duration_range(120, 1, 7200, "contactPrePassDurationSeconds")
        validate_duration_range(1, 1, 7200, "contactPrePassDurationSeconds")  # Min
        validate_duration_range(7200, 1, 7200, "contactPrePassDurationSeconds")  # Max

    def test_invalid_contact_pre_pass_duration(self):
        """Test invalid contact pre-pass duration."""
        with pytest.raises(InvalidParameterException):
            validate_duration_range(0, 1, 7200, "contactPrePassDurationSeconds")

        with pytest.raises(InvalidParameterException):
            validate_duration_range(7201, 1, 7200, "contactPrePassDurationSeconds")

    def test_valid_minimum_viable_contact_duration(self):
        """Test valid minimum viable contact duration."""
        validate_duration_range(60, 1, 21600, "minimumViableContactDurationSeconds")
        validate_duration_range(1, 1, 21600, "minimumViableContactDurationSeconds")
        validate_duration_range(21600, 1, 21600, "minimumViableContactDurationSeconds")

    def test_invalid_minimum_viable_contact_duration(self):
        """Test invalid minimum viable contact duration."""
        with pytest.raises(InvalidParameterException):
            validate_duration_range(0, 1, 21600, "minimumViableContactDurationSeconds")

        with pytest.raises(InvalidParameterException):
            validate_duration_range(21601, 1, 21600, "minimumViableContactDurationSeconds")


class TestTagsValidation:
    """Tests for tags validation."""

    def test_valid_tags(self):
        """Test that valid tags pass validation."""
        tags = {"Environment": "production", "Project": "satellite", "Team": "ops"}
        validate_tags(tags)  # Should not raise

    def test_empty_tags(self):
        """Test that empty tags dict is valid."""
        validate_tags({})  # Should not raise

    def test_too_many_tags(self):
        """Test that more than 50 tags is rejected."""
        tags = {f"key{i}": f"value{i}" for i in range(51)}

        with pytest.raises(InvalidParameterException) as exc:
            validate_tags(tags)

        assert "Cannot have more than 50 tags" in str(exc.value)

    def test_empty_tag_key(self):
        """Test that empty tag key is rejected."""
        tags = {"": "value"}

        with pytest.raises(InvalidParameterException) as exc:
            validate_tags(tags)

        assert "Tag key cannot be empty" in str(exc.value)

    def test_tag_key_too_long(self):
        """Test that tag key longer than 128 characters is rejected."""
        tags = {"a" * 129: "value"}

        with pytest.raises(InvalidParameterException) as exc:
            validate_tags(tags)

        assert "Tag key cannot exceed 128 characters" in str(exc.value)

    def test_tag_value_too_long(self):
        """Test that tag value longer than 256 characters is rejected."""
        tags = {"key": "v" * 257}

        with pytest.raises(InvalidParameterException) as exc:
            validate_tags(tags)

        assert "Tag value cannot exceed 256 characters" in str(exc.value)

    def test_maximum_valid_tag_lengths(self):
        """Test tag key and value at maximum valid lengths."""
        tags = {"k" * 128: "v" * 256}
        validate_tags(tags)  # Should not raise
