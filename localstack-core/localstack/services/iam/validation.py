"""
Validation utilities for IAM resources.

This module provides validation functions for IAM names, paths, ARNs, and policy documents
following AWS IAM validation rules.
"""

import json
import re
from typing import Optional

from localstack.aws.api.iam import (
    EntityAlreadyExistsException,
    InvalidInputException,
    LimitExceededException,
    MalformedPolicyDocumentException,
    NoSuchEntityException,
)

# =============================================================================
# Constants - IAM Validation Patterns
# =============================================================================

# Name patterns for IAM resources
# See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
IAM_NAME_PATTERN = re.compile(r"^[\w+=,.@-]+$")
IAM_NAME_MIN_LENGTH = 1
IAM_NAME_MAX_LENGTH_USER_ROLE_GROUP = 64
IAM_NAME_MAX_LENGTH_POLICY = 128
IAM_NAME_MAX_LENGTH_INSTANCE_PROFILE = 128

# Path pattern for IAM resources
# Path must start and end with / and contain alphanumeric, . _ or -
IAM_PATH_PATTERN = re.compile(r"^(/[a-zA-Z0-9._-]+)*/?$")
IAM_PATH_MIN_LENGTH = 1
IAM_PATH_MAX_LENGTH = 512

# ARN patterns
IAM_ARN_PATTERN = re.compile(
    r"^arn:aws:iam::(\d{12}|aws):(user|role|group|policy|instance-profile|mfa|saml-provider|oidc-provider|server-certificate)(/[\w+=,.@/-]+)?$"
)
POLICY_ARN_PATTERN = re.compile(r"^arn:aws:iam::(\d{12}|aws):policy(/[\w+=,.@/-]+)?$")

# Policy document limits
POLICY_DOCUMENT_MAX_SIZE = 6144  # bytes
TRUST_POLICY_MAX_SIZE = 2048  # bytes
INLINE_POLICY_NAME_MAX_LENGTH = 128

# Resource limits
MAX_USERS_PER_ACCOUNT = 5000
MAX_GROUPS_PER_ACCOUNT = 300
MAX_ROLES_PER_ACCOUNT = 1000
MAX_POLICIES_PER_ACCOUNT = 1500
MAX_GROUPS_PER_USER = 10
MAX_ATTACHED_POLICIES_PER_PRINCIPAL = 10
MAX_POLICY_VERSIONS = 5
MAX_ACCESS_KEYS_PER_USER = 2
MAX_MFA_DEVICES_PER_USER = 8
MAX_TAGS_PER_RESOURCE = 50
MAX_TAG_KEY_LENGTH = 128
MAX_TAG_VALUE_LENGTH = 256

# =============================================================================
# Name Validation
# =============================================================================


def validate_iam_name(
    name: str,
    entity_type: str,
    max_length: int = IAM_NAME_MAX_LENGTH_USER_ROLE_GROUP,
) -> None:
    """
    Validate an IAM resource name.

    :param name: The name to validate
    :param entity_type: Type of entity for error messages (e.g., "user", "role")
    :param max_length: Maximum allowed length
    :raises InvalidInputException: If the name is invalid
    """
    if not name:
        raise InvalidInputException(f"The {entity_type} name cannot be empty.")

    if len(name) < IAM_NAME_MIN_LENGTH:
        raise InvalidInputException(
            f"The {entity_type} name must be at least {IAM_NAME_MIN_LENGTH} character(s) long."
        )

    if len(name) > max_length:
        raise InvalidInputException(
            f"The {entity_type} name must be no more than {max_length} character(s) long."
        )

    if not IAM_NAME_PATTERN.match(name):
        raise InvalidInputException(
            f"The {entity_type} name '{name}' is not valid. "
            "Names must match the pattern [\\w+=,.@-]+"
        )


def validate_user_name(name: str) -> None:
    """Validate an IAM user name."""
    validate_iam_name(name, "user", IAM_NAME_MAX_LENGTH_USER_ROLE_GROUP)


def validate_role_name(name: str) -> None:
    """Validate an IAM role name."""
    validate_iam_name(name, "role", IAM_NAME_MAX_LENGTH_USER_ROLE_GROUP)


def validate_group_name(name: str) -> None:
    """Validate an IAM group name."""
    validate_iam_name(name, "group", IAM_NAME_MAX_LENGTH_USER_ROLE_GROUP)


def validate_policy_name(name: str) -> None:
    """Validate an IAM policy name."""
    validate_iam_name(name, "policy", IAM_NAME_MAX_LENGTH_POLICY)


def validate_instance_profile_name(name: str) -> None:
    """Validate an instance profile name."""
    validate_iam_name(name, "instance profile", IAM_NAME_MAX_LENGTH_INSTANCE_PROFILE)


def validate_inline_policy_name(name: str) -> None:
    """Validate an inline policy name."""
    validate_iam_name(name, "inline policy", INLINE_POLICY_NAME_MAX_LENGTH)


# =============================================================================
# Path Validation
# =============================================================================


def validate_path(path: Optional[str], entity_type: str = "resource") -> str:
    """
    Validate and normalize an IAM path.

    :param path: The path to validate (can be None, defaults to "/")
    :param entity_type: Type of entity for error messages
    :return: Normalized path (always starts and ends with "/")
    :raises InvalidInputException: If the path is invalid
    """
    if path is None:
        return "/"

    if not path:
        return "/"

    # Normalize path to start and end with /
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path + "/"

    if len(path) > IAM_PATH_MAX_LENGTH:
        raise InvalidInputException(
            f"The path for the {entity_type} must be no more than {IAM_PATH_MAX_LENGTH} characters."
        )

    # Special case: "/" is always valid
    if path == "/":
        return path

    # Remove the trailing slash for pattern matching, then add it back
    path_to_check = path.rstrip("/")
    if not IAM_PATH_PATTERN.match(path_to_check):
        raise InvalidInputException(
            f"The path '{path}' is not valid. "
            "Paths must start with a slash and contain alphanumeric characters, ., _ or -"
        )

    return path


# =============================================================================
# ARN Validation
# =============================================================================


def validate_policy_arn(arn: str) -> None:
    """
    Validate a policy ARN.

    :param arn: The ARN to validate
    :raises InvalidInputException: If the ARN is invalid
    """
    if not arn:
        raise InvalidInputException("Policy ARN cannot be empty.")

    if not POLICY_ARN_PATTERN.match(arn):
        raise InvalidInputException(f"ARN {arn} is not valid.")


def validate_arn(arn: str) -> None:
    """
    Validate a general IAM ARN.

    :param arn: The ARN to validate
    :raises InvalidInputException: If the ARN is invalid
    """
    if not arn:
        raise InvalidInputException("ARN cannot be empty.")

    if not IAM_ARN_PATTERN.match(arn):
        raise InvalidInputException(f"ARN {arn} is not valid.")


def is_aws_managed_policy_arn(arn: str) -> bool:
    """
    Check if an ARN refers to an AWS managed policy.

    AWS managed policies have account ID "aws" in their ARN.
    """
    return arn.startswith("arn:aws:iam::aws:policy/")


# =============================================================================
# Policy Document Validation
# =============================================================================


def validate_policy_document(
    document: str,
    is_trust_policy: bool = False,
    policy_name: str = "policy",
) -> dict:
    """
    Validate a policy document.

    :param document: JSON policy document string
    :param is_trust_policy: If True, use trust policy size limit
    :param policy_name: Name for error messages
    :return: Parsed policy document as dict
    :raises MalformedPolicyDocumentException: If the document is invalid
    """
    if not document:
        raise MalformedPolicyDocumentException(
            f"The {policy_name} document cannot be empty."
        )

    # Check size limits
    max_size = TRUST_POLICY_MAX_SIZE if is_trust_policy else POLICY_DOCUMENT_MAX_SIZE
    doc_size = len(document.encode("utf-8"))
    if doc_size > max_size:
        raise MalformedPolicyDocumentException(
            f"The {policy_name} document exceeds the maximum allowed size ({doc_size} > {max_size} bytes)."
        )

    # Parse JSON
    try:
        policy = json.loads(document)
    except json.JSONDecodeError as e:
        raise MalformedPolicyDocumentException(
            f"The {policy_name} document contains invalid JSON: {str(e)}"
        )

    # Validate structure
    if not isinstance(policy, dict):
        raise MalformedPolicyDocumentException(
            f"The {policy_name} document must be a JSON object."
        )

    # Validate required fields
    if "Version" not in policy:
        # AWS allows missing Version (defaults to 2008-10-17), but we validate presence
        pass  # Be lenient like AWS

    if "Statement" not in policy:
        raise MalformedPolicyDocumentException(
            f"The {policy_name} document must contain a Statement element."
        )

    statements = policy["Statement"]
    if not isinstance(statements, list):
        # Single statement can be a dict
        if not isinstance(statements, dict):
            raise MalformedPolicyDocumentException(
                f"The {policy_name} document Statement must be an array or object."
            )
        statements = [statements]

    # Validate each statement
    for i, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise MalformedPolicyDocumentException(
                f"Statement {i + 1} must be an object."
            )

        # Effect is required
        if "Effect" not in statement:
            raise MalformedPolicyDocumentException(
                f"Statement {i + 1} is missing required element 'Effect'."
            )

        effect = statement["Effect"]
        if effect not in ("Allow", "Deny"):
            raise MalformedPolicyDocumentException(
                f"Statement {i + 1} has invalid Effect '{effect}'. Effect must be 'Allow' or 'Deny'."
            )

        # For trust policies, Principal is required; for regular policies, Action is required
        if is_trust_policy:
            if "Principal" not in statement and "NotPrincipal" not in statement:
                raise MalformedPolicyDocumentException(
                    f"Statement {i + 1} is missing required element 'Principal' or 'NotPrincipal'."
                )
        else:
            if "Action" not in statement and "NotAction" not in statement:
                raise MalformedPolicyDocumentException(
                    f"Statement {i + 1} is missing required element 'Action' or 'NotAction'."
                )

    return policy


def validate_trust_policy_document(document: str) -> dict:
    """
    Validate a role trust policy (assume role policy) document.

    :param document: JSON trust policy document string
    :return: Parsed policy document as dict
    """
    return validate_policy_document(document, is_trust_policy=True, policy_name="trust policy")


# =============================================================================
# Tag Validation
# =============================================================================


def validate_tags(tags: list[dict]) -> dict[str, str]:
    """
    Validate IAM tags and convert to internal format.

    :param tags: List of tag dicts with 'Key' and 'Value'
    :return: Dict mapping tag keys to values
    :raises InvalidInputException: If tags are invalid
    :raises LimitExceededException: If too many tags
    """
    if not tags:
        return {}

    if len(tags) > MAX_TAGS_PER_RESOURCE:
        raise LimitExceededException(
            f"Cannot assign more than {MAX_TAGS_PER_RESOURCE} tags to a resource."
        )

    result = {}
    for tag in tags:
        key = tag.get("Key", "")
        value = tag.get("Value", "")

        if not key:
            raise InvalidInputException("Tag key cannot be empty.")

        if len(key) > MAX_TAG_KEY_LENGTH:
            raise InvalidInputException(
                f"Tag key length exceeds maximum of {MAX_TAG_KEY_LENGTH} characters."
            )

        if len(value) > MAX_TAG_VALUE_LENGTH:
            raise InvalidInputException(
                f"Tag value length exceeds maximum of {MAX_TAG_VALUE_LENGTH} characters."
            )

        # Check for reserved aws: prefix
        if key.startswith("aws:"):
            raise InvalidInputException(
                "Tag keys starting with 'aws:' are reserved for AWS use."
            )

        result[key] = value

    return result


def tags_to_list(tags: dict[str, str]) -> list[dict]:
    """
    Convert internal tag format to AWS API format.

    :param tags: Dict mapping tag keys to values
    :return: List of tag dicts with 'Key' and 'Value'
    """
    return [{"Key": k, "Value": v} for k, v in tags.items()]


# =============================================================================
# Resource Limit Validation
# =============================================================================


def check_user_limit(current_count: int) -> None:
    """Check if adding a user would exceed the limit."""
    if current_count >= MAX_USERS_PER_ACCOUNT:
        raise LimitExceededException(
            f"Cannot exceed quota for UsersPerAccount: {MAX_USERS_PER_ACCOUNT}"
        )


def check_group_limit(current_count: int) -> None:
    """Check if adding a group would exceed the limit."""
    if current_count >= MAX_GROUPS_PER_ACCOUNT:
        raise LimitExceededException(
            f"Cannot exceed quota for GroupsPerAccount: {MAX_GROUPS_PER_ACCOUNT}"
        )


def check_role_limit(current_count: int) -> None:
    """Check if adding a role would exceed the limit."""
    if current_count >= MAX_ROLES_PER_ACCOUNT:
        raise LimitExceededException(
            f"Cannot exceed quota for RolesPerAccount: {MAX_ROLES_PER_ACCOUNT}"
        )


def check_policy_limit(current_count: int) -> None:
    """Check if adding a policy would exceed the limit."""
    if current_count >= MAX_POLICIES_PER_ACCOUNT:
        raise LimitExceededException(
            f"Cannot exceed quota for PoliciesPerAccount: {MAX_POLICIES_PER_ACCOUNT}"
        )


def check_groups_per_user_limit(current_count: int) -> None:
    """Check if adding a user to a group would exceed the limit."""
    if current_count >= MAX_GROUPS_PER_USER:
        raise LimitExceededException(
            f"Cannot exceed quota for GroupsPerUser: {MAX_GROUPS_PER_USER}"
        )


def check_attached_policies_limit(current_count: int, principal_type: str = "user") -> None:
    """Check if attaching a policy would exceed the limit."""
    if current_count >= MAX_ATTACHED_POLICIES_PER_PRINCIPAL:
        raise LimitExceededException(
            f"Cannot exceed quota for AttachedPoliciesPerUser: {MAX_ATTACHED_POLICIES_PER_PRINCIPAL}"
        )


def check_policy_versions_limit(current_count: int) -> None:
    """Check if creating a policy version would exceed the limit."""
    if current_count >= MAX_POLICY_VERSIONS:
        raise LimitExceededException(
            f"A managed policy can have up to {MAX_POLICY_VERSIONS} versions. "
            "Delete one or more versions before creating a new one."
        )


def check_access_keys_limit(current_count: int) -> None:
    """Check if creating an access key would exceed the limit."""
    if current_count >= MAX_ACCESS_KEYS_PER_USER:
        raise LimitExceededException(
            f"Cannot exceed quota for AccessKeysPerUser: {MAX_ACCESS_KEYS_PER_USER}"
        )


def check_mfa_devices_limit(current_count: int) -> None:
    """Check if adding an MFA device would exceed the limit."""
    if current_count >= MAX_MFA_DEVICES_PER_USER:
        raise LimitExceededException(
            f"Cannot exceed quota for MFADevicesPerUser: {MAX_MFA_DEVICES_PER_USER}"
        )


# =============================================================================
# Entity Existence Checks
# =============================================================================


def entity_exists_error(entity_type: str, entity_name: str) -> EntityAlreadyExistsException:
    """Create an EntityAlreadyExistsException for the given entity."""
    return EntityAlreadyExistsException(
        f"{entity_type.capitalize()} with name {entity_name} already exists."
    )


def entity_not_found_error(entity_type: str, entity_name: str) -> NoSuchEntityException:
    """Create a NoSuchEntityException for the given entity."""
    return NoSuchEntityException(
        f"The {entity_type} with name {entity_name} cannot be found."
    )
