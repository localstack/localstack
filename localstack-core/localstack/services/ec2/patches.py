import logging
from typing import Optional

from moto.ec2 import models as ec2_models

from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.services.ec2.exceptions import (
    InvalidSecurityGroupDuplicateCustomIdError,
    InvalidSubnetDuplicateCustomIdError,
    InvalidVpcDuplicateCustomIdError,
)
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)


def apply_patches():
    @patch(ec2_models.subnets.SubnetBackend.create_subnet)
    def ec2_create_subnet(
        fn: ec2_models.subnets.SubnetBackend.create_subnet,
        self: ec2_models.subnets.SubnetBackend,
        *args,
        tags: Optional[dict[str, str]] = None,
        **kwargs,
    ):
        tags: dict[str, str] = tags or {}
        custom_id: Optional[str] = tags.get("subnet", {}).get(TAG_KEY_CUSTOM_ID)
        vpc_id: str = args[0] if len(args) >= 1 else kwargs["vpc_id"]

        if custom_id:
            # Check if custom id is unique within a given VPC
            for az_subnets in self.subnets.values():
                for subnet in az_subnets.values():
                    if subnet.vpc_id == vpc_id and subnet.id == custom_id:
                        raise InvalidSubnetDuplicateCustomIdError(custom_id)

        # Generate subnet with moto library
        result: ec2_models.subnets.Subnet = fn(self, *args, tags=tags, **kwargs)
        availability_zone = result.availability_zone

        if custom_id:
            # Remove the subnet from the default dict and add it back with the custom id
            self.subnets[availability_zone].pop(result.id)
            result.id = custom_id
            self.subnets[availability_zone][custom_id] = result

        # Return the subnet with the patched custom id
        return result

    @patch(ec2_models.security_groups.SecurityGroupBackend.create_security_group)
    def ec2_create_security_group(
        fn: ec2_models.security_groups.SecurityGroupBackend.create_security_group,
        self: ec2_models.security_groups.SecurityGroupBackend,
        *args,
        tags: Optional[dict[str, str]] = None,
        force: bool = False,
        **kwargs,
    ):
        # Extract tags and custom ID
        tags: dict[str, str] = tags or {}
        custom_id = tags.get(TAG_KEY_CUSTOM_ID)
        vpc_id: str = kwargs["vpc_id"] if "vpc_id" in kwargs else args[2]

        # Check if custom id is unique
        if not force and custom_id in self.groups[vpc_id]:
            raise InvalidSecurityGroupDuplicateCustomIdError(custom_id)

        # Generate security group with moto library
        result: ec2_models.security_groups.SecurityGroup = fn(
            self, *args, tags=tags, force=force, **kwargs
        )

        if custom_id:
            # Remove the security group from the default dict and add it back with the custom id
            self.groups[vpc_id].pop(result.group_id)
            result.group_id = result.id = custom_id
            self.groups[vpc_id][custom_id] = result

        return result

    @patch(ec2_models.vpcs.VPCBackend.create_vpc)
    def ec2_create_vpc(
        fn: ec2_models.vpcs.VPCBackend.create_vpc,
        self: ec2_models.vpcs.VPCBackend,
        *args,
        tags: Optional[list[dict[str, str]]] = None,
        is_default: bool = False,
        **kwargs,
    ):
        # Extract custom ID from tags if it exists
        tags: list[dict[str, str]] = tags or []
        custom_ids = [tag["Value"] for tag in tags if tag["Key"] == TAG_KEY_CUSTOM_ID]
        custom_id = custom_ids[0] if len(custom_ids) > 0 else None

        # Check if custom id is unique
        if custom_id and custom_id in self.vpcs:
            raise InvalidVpcDuplicateCustomIdError(custom_id)

        # Generate VPC with moto library
        result: ec2_models.vpcs.VPC = fn(self, *args, tags=tags, is_default=is_default, **kwargs)
        vpc_id = result.id

        if custom_id:
            # Remove security group associated with unique non-custom VPC ID
            default = self.get_security_group_from_name("default", vpc_id=vpc_id)
            if not default:
                self.delete_security_group(
                    name="default",
                    vpc_id=vpc_id,
                )

            # Delete route table if only main route table remains.
            for route_table in self.describe_route_tables(filters={"vpc-id": vpc_id}):
                self.delete_route_table(route_table.id)  # type: ignore[attr-defined]

            # Remove the VPC from the default dict and add it back with the custom id
            self.vpcs.pop(vpc_id)
            result.id = custom_id
            self.vpcs[custom_id] = result

            # Create default network ACL, route table, and security group for custom ID VPC
            self.create_route_table(
                vpc_id=custom_id,
                main=True,
            )
            self.create_network_acl(
                vpc_id=custom_id,
                default=True,
            )
            # Associate default security group with custom ID VPC
            if not default:
                self.create_security_group(
                    name="default",
                    description="default VPC security group",
                    vpc_id=custom_id,
                    is_default=is_default,
                )

        return result
