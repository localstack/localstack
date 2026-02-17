import logging
from datetime import datetime

import pyotp
import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# TODO remove after new IAM implementation of MFA devices
pytestmark = pytest.mark.skip


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())
    # Binary data transformers - these are non-deterministic and are bytes, not strings
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "Base32StringSeed", value_replacement="<base32-seed>", reference_replacement=False
        )
    )
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "QRCodePNG", value_replacement="<qr-code-png>", reference_replacement=False
        )
    )


@pytest.fixture
def create_virtual_mfa_device(aws_client):
    """Factory fixture to create virtual MFA devices with automatic cleanup."""
    created_devices = []

    def _create_device(*args, **kwargs):
        response = aws_client.iam.create_virtual_mfa_device(*args, **kwargs)
        serial_number = response["VirtualMFADevice"]["SerialNumber"]
        created_devices.append(serial_number)
        return response

    yield _create_device

    # Cleanup
    for serial_number in created_devices:
        try:
            # First try to deactivate if it was enabled for a user
            # List all MFA devices to see if this one is attached to a user
            devices = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")[
                "VirtualMFADevices"
            ]
            for device in devices:
                if device["SerialNumber"] == serial_number and "User" in device:
                    try:
                        aws_client.iam.deactivate_mfa_device(
                            UserName=device["User"]["UserName"],
                            SerialNumber=serial_number,
                        )
                    except ClientError:
                        LOG.debug(
                            "Could not deactivate MFA device %s during cleanup", serial_number
                        )
            # Now delete the device
            aws_client.iam.delete_virtual_mfa_device(SerialNumber=serial_number)
        except ClientError as e:
            LOG.debug("Could not delete MFA device %s during cleanup: %s", serial_number, e)


class TestVirtualMfaDevice:
    """Tests for virtual MFA device CRUD operations."""

    @markers.aws.validated
    @pytest.mark.parametrize("path", [None, "/", "/test-path/", "/test//double/"])
    def test_virtual_mfa_device_lifecycle(
        self, aws_client, snapshot, create_virtual_mfa_device, account_id, partition, path
    ):
        """Test create, list, and delete virtual MFA device operations."""
        device_name = f"mfa-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(device_name, "<mfa-device-name>"))

        # Create virtual MFA device
        kwargs = {}
        if path is not None:
            kwargs["Path"] = path
        create_response = create_virtual_mfa_device(VirtualMFADeviceName=device_name, **kwargs)
        serial_number = create_response["VirtualMFADevice"]["SerialNumber"]
        snapshot.match("create-mfa-device", create_response)

        # Verify the device appears in list
        list_response = aws_client.iam.list_virtual_mfa_devices()
        list_response["VirtualMFADevices"] = [
            d for d in list_response["VirtualMFADevices"] if d["SerialNumber"] == serial_number
        ]
        snapshot.match("list-mfa-devices", list_response)

        # Delete the device
        delete_response = aws_client.iam.delete_virtual_mfa_device(SerialNumber=serial_number)
        snapshot.match("delete-mfa-device", delete_response)

        # Verify device is no longer in list
        list_after_delete = aws_client.iam.list_virtual_mfa_devices()
        assert serial_number not in [
            d["SerialNumber"] for d in list_after_delete["VirtualMFADevices"]
        ], "Device should not exist after deletion"

    @markers.aws.validated
    def test_virtual_mfa_device_errors(
        self, aws_client, snapshot, create_virtual_mfa_device, account_id, partition
    ):
        """Test error cases for virtual MFA device operations."""
        device_name = f"mfa-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(device_name, "<mfa-device-name>"))

        # Create a device first
        create_response = create_virtual_mfa_device(VirtualMFADeviceName=device_name)
        snapshot.match("create-mfa-device", create_response)

        # Try to create duplicate device (same name at default path)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)
        snapshot.match("create-duplicate-error", exc.value.response)

        # Try invalid path (doesn't start with /)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_virtual_mfa_device(
                VirtualMFADeviceName=f"mfa-{short_uid()}", Path="invalid-path/"
            )
        snapshot.match("create-invalid-path-no-leading-slash-error", exc.value.response)

        # Try invalid path (doesn't end with /)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_virtual_mfa_device(
                VirtualMFADeviceName=f"mfa-{short_uid()}", Path="/invalid-path"
            )
        snapshot.match("create-invalid-path-no-trailing-slash-error", exc.value.response)

        # Try path that's too long (>512 chars)
        long_path = "/" + "a" * 512 + "/"
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_virtual_mfa_device(
                VirtualMFADeviceName=f"mfa-{short_uid()}", Path=long_path
            )
        snapshot.match("create-path-too-long-error", exc.value.response)

        # Try to delete non-existent device
        nonexistent_serial = f"arn:{partition}:iam::{account_id}:mfa/nonexistent-device"
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_virtual_mfa_device(SerialNumber=nonexistent_serial)
        snapshot.match("delete-nonexistent-error", exc.value.response)

    @markers.aws.validated
    def test_list_virtual_mfa_devices(self, aws_client, snapshot, create_virtual_mfa_device):
        """Test listing virtual MFA devices with filtering and pagination."""
        # Sort by SerialNumber since list order is not guaranteed
        snapshot.add_transformer(
            SortingTransformer("VirtualMFADevices", lambda x: x["SerialNumber"])
        )
        # Create multiple MFA devices - use same prefix for consistent replacement
        device_names = [f"mfa-list-{idx}-{short_uid()}" for idx in range(3)]
        # Use regex to replace all device names with a generic placeholder
        for idx, name in enumerate(device_names):
            snapshot.add_transformer(snapshot.transform.regex(name, f"<mfa-device-name-{idx}>"))
        serial_numbers = []
        for idx, name in enumerate(device_names):
            response = create_virtual_mfa_device(VirtualMFADeviceName=name)
            snapshot.match(f"create-virtual-mfa-device-{idx}", response)
            serial_numbers.append(response["VirtualMFADevice"]["SerialNumber"])

        # List all unassigned devices (our devices should appear)
        list_unassigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")
        list_unassigned["VirtualMFADevices"] = [
            d for d in list_unassigned["VirtualMFADevices"] if d["SerialNumber"] in serial_numbers
        ]
        snapshot.match("list-unassigned", list_unassigned)

        # List assigned devices (should be empty for our devices)
        list_assigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
        list_assigned["VirtualMFADevices"] = [
            d for d in list_assigned["VirtualMFADevices"] if d["SerialNumber"] in serial_numbers
        ]
        snapshot.match("list-assigned", list_assigned)

        # List with Any status (should include our devices)
        list_any = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Any")
        list_any["VirtualMFADevices"] = [
            d for d in list_any["VirtualMFADevices"] if d["SerialNumber"] in serial_numbers
        ]
        snapshot.match("list-any", list_any)

        # Test pagination with MaxItems
        list_paginated = aws_client.iam.list_virtual_mfa_devices(MaxItems=1)
        # Just verify structure, not content (other tests may have created devices)
        assert "VirtualMFADevices" in list_paginated
        assert len(list_paginated["VirtualMFADevices"]) == 1
        assert list_paginated["IsTruncated"]

        # If there's a marker, use it for the next page
        list_next_page = aws_client.iam.list_virtual_mfa_devices(
            Marker=list_paginated["Marker"], MaxItems=1
        )
        assert "VirtualMFADevices" in list_next_page

        # Test invalid marker
        with pytest.raises(ClientError) as exc:
            aws_client.iam.list_virtual_mfa_devices(Marker="invalid-marker-value")
        snapshot.match("list-invalid-marker-error", exc.value.response)

    @markers.aws.validated
    def test_enable_virtual_mfa_device(
        self, aws_client, snapshot, create_virtual_mfa_device, create_user
    ):
        """Test enabling and deactivating virtual MFA device for a user.

        Note: This test is LocalStack-only because AWS requires valid TOTP codes
        generated from the Base32StringSeed, which cannot be easily done in tests.
        """
        # Create a user
        user_name = f"user-{short_uid()}"

        # Create a virtual MFA device
        device_name = f"mfa-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(device_name, "<mfa-device-name>"))

        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        create_device_response = create_virtual_mfa_device(VirtualMFADeviceName=device_name)
        serial_number = create_device_response["VirtualMFADevice"]["SerialNumber"]
        snapshot.match("create-mfa-device", create_device_response)

        # List MFA devices for user (should be empty)
        list_mfa_before = aws_client.iam.list_mfa_devices(UserName=user_name)
        snapshot.match("list-mfa-devices-before", list_mfa_before)
        # TODO use pyotp library to allow snapshot validation
        otp = pyotp.TOTP(create_device_response["VirtualMFADevice"]["Base32StringSeed"])
        # generate the last and the current auth code at once
        current_time = datetime.now()
        authcode_1 = otp.at(current_time, counter_offset=-1)
        authcode_2 = otp.at(current_time)

        # Enable MFA device for user
        # Note: LocalStack accepts any 6-digit codes; AWS requires valid TOTP codes
        enable_response = aws_client.iam.enable_mfa_device(
            UserName=user_name,
            SerialNumber=serial_number,
            AuthenticationCode1=authcode_1,
            AuthenticationCode2=authcode_2,
        )
        snapshot.match("enable-mfa-device", enable_response)

        # List MFA devices for user (should now have the device)
        list_mfa_after = aws_client.iam.list_mfa_devices(UserName=user_name)
        snapshot.match("list-mfa-devices-after", list_mfa_after)

        # List virtual MFA devices - verify device is now assigned and has User info
        list_assigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
        list_assigned["VirtualMFADevices"] = [
            d for d in list_assigned["VirtualMFADevices"] if d["SerialNumber"] == serial_number
        ]
        snapshot.match("list-assigned-with-user", list_assigned)

        # Verify unassigned list no longer has our device
        list_unassigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")
        assert serial_number not in [
            d["SerialNumber"] for d in list_unassigned["VirtualMFADevices"]
        ], "Assigned device should not appear in unassigned list"

        # Deactivate MFA device
        deactivate_response = aws_client.iam.deactivate_mfa_device(
            UserName=user_name, SerialNumber=serial_number
        )
        snapshot.match("deactivate-mfa-device", deactivate_response)

        # Verify MFA device is now unassigned
        list_mfa_after_deactivate = aws_client.iam.list_mfa_devices(UserName=user_name)
        snapshot.match("list-mfa-devices-after-deactivate", list_mfa_after_deactivate)

        list_assigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
        assert serial_number not in [
            d["SerialNumber"] for d in list_assigned["VirtualMFADevices"]
        ], "Unassigned device should not appear in assigned list"

        # Verify unassigned list no longer has our device
        list_unassigned = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Unassigned")
        list_unassigned["VirtualMFADevices"] = [
            d for d in list_assigned["VirtualMFADevices"] if d["SerialNumber"] == serial_number
        ]
        snapshot.match("list-unassigned-after-deactivation", list_assigned)

    @markers.aws.validated
    def test_enable_mfa_device_errors(
        self, aws_client, snapshot, create_virtual_mfa_device, create_user, account_id, partition
    ):
        """Test error cases for enable/deactivate MFA device operations."""
        # Create a virtual MFA device for error testing
        device_name = f"mfa-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(device_name, "<mfa-device-name>"))
        create_device_response = create_virtual_mfa_device(VirtualMFADeviceName=device_name)
        serial_number = create_device_response["VirtualMFADevice"]["SerialNumber"]

        # Try to enable MFA device for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.enable_mfa_device(
                UserName="nonexistent-user",
                SerialNumber=serial_number,
                AuthenticationCode1="123456",
                AuthenticationCode2="654321",
            )
        snapshot.match("enable-mfa-nonexistent-user-error", exc.value.response)

        # Try to deactivate MFA device for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.deactivate_mfa_device(
                UserName="nonexistent-user", SerialNumber=serial_number
            )
        snapshot.match("deactivate-mfa-nonexistent-user-error", exc.value.response)

        # Try to deactivate non-existent MFA device for existing user
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)
        nonexistent_serial = f"arn:{partition}:iam::{account_id}:mfa/nonexistent-mfa"
        with pytest.raises(ClientError) as exc:
            aws_client.iam.deactivate_mfa_device(
                UserName=user_name, SerialNumber=nonexistent_serial
            )
        snapshot.match("deactivate-nonexistent-mfa-error", exc.value.response)

    @markers.aws.only_localstack
    def test_physical_token_mfa(self, aws_client, create_user):
        """Test activating a physical token MFA. This should always succeed, but we cannot do anything with that token. Lacking a token, we also cannot validate that test."""
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)
        serial_number = "GAHT12345678"

        aws_client.iam.enable_mfa_device(
            UserName=user_name,
            SerialNumber=serial_number,
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )

        response = aws_client.iam.list_mfa_devices(UserName=user_name)
        device = response["MFADevices"][0]
        assert device["SerialNumber"] == serial_number

        aws_client.iam.deactivate_mfa_device(UserName=user_name, SerialNumber=serial_number)
        response = aws_client.iam.list_mfa_devices(UserName=user_name)
        assert not response["MFADevices"]
