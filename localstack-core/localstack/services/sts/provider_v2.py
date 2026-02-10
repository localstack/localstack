"""
STS v2 Provider - A moto-independent implementation of AWS STS.
"""

import base64
import logging
import re
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree

from botocore.exceptions import ClientError
from moto.iam.models import User as MotoUser
from moto.iam.models import iam_backends

from localstack.aws.api import CommonServiceException, RequestContext, ServiceException
from localstack.aws.api.sts import (
    AssumedRoleUser,
    AssumeRoleResponse,
    AssumeRoleWithSAMLResponse,
    AssumeRoleWithWebIdentityResponse,
    Credentials,
    FederatedUser,
    GetAccessKeyInfoResponse,
    GetCallerIdentityResponse,
    GetFederationTokenResponse,
    GetSessionTokenResponse,
    ProvidedContextsListType,
    SAMLAssertionType,
    StsApi,
    arnType,
    clientTokenType,
    durationSecondsType,
    externalIdType,
    policyDescriptorListType,
    roleDurationSecondsType,
    roleSessionNameType,
    serialNumberType,
    sessionPolicyDocumentType,
    sourceIdentityType,
    tagKeyListType,
    tagListType,
    tokenCodeType,
    unrestrictedSessionPolicyDocumentType,
    urlType,
    userNameType,
)
from localstack.aws.connect import connect_to
from localstack.constants import INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sts.models import (
    DEFAULT_SESSION_DURATION,
    MAX_FEDERATION_TOKEN_POLICY_LENGTH,
    MAX_ROLE_SESSION_NAME_LENGTH,
    MIN_SESSION_DURATION,
    SessionConfig,
    TemporaryCredentials,
    generate_access_key_id,
    generate_role_id,
    generate_secret_access_key,
    generate_session_token,
    sts_stores_v2,
)
from localstack.state import StateVisitor
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    extract_resource_from_arn,
)
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)

# Regex patterns for validation
ROLE_ARN_REGEX = re.compile(r"^arn:[^:]+:[^:]+:[^:]*:[^:]*:[^:]+$")
SESSION_NAME_REGEX = re.compile(r"^[\w+=,.@-]*$")

# SAML namespace
SAML_NAMESPACE = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
}


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class InvalidParameterValueError(ServiceException):
    code = "InvalidParameterValue"
    status_code = 400
    sender_fault = True


class PackedPolicyTooLargeException(ServiceException):
    code = "PackedPolicyTooLarge"
    status_code = 400
    sender_fault = True


class StsProviderV2(StsApi, ServiceLifecycleHook):
    """
    STS Provider v2 - moto-independent implementation.
    """

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(sts_stores_v2)

    def _get_store(self, account_id: str, region: str):
        """Get the STS store for the given account and region."""
        return sts_stores_v2[account_id][region]

    def _get_role_from_arn(self, role_arn: str):
        try:
            target_account_id = extract_account_id_from_arn(role_arn)
            target_region = extract_region_from_arn(role_arn)
            role_name = extract_resource_from_arn(role_arn).split("/")[-1]

            iam_client = connect_to(
                aws_access_key_id=target_account_id,
                aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
                region_name=target_region,
            ).iam.request_metadata(service_principal="sts")

            return iam_client.get_role(RoleName=role_name)["Role"]
        except ClientError:
            return None

    def _create_credentials(
        self,
        account_id: str,
        arn: str,
        user_id: str,
        duration_seconds: int,
        session_config: SessionConfig | None = None,
        source_identity: str | None = None,
    ) -> TemporaryCredentials:
        """Create and store temporary credentials."""
        access_key_id = generate_access_key_id()
        secret_access_key = generate_secret_access_key()
        session_token = generate_session_token()
        expiration = datetime.now(UTC) + timedelta(seconds=duration_seconds)

        creds = TemporaryCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
            account_id=account_id,
            arn=arn,
            user_id=user_id,
            source_identity=source_identity,
        )

        # Store credentials globally for lookup
        store = self._get_store(account_id, "us-east-1")
        store.credentials[access_key_id] = creds

        if session_config:
            store.sessions[access_key_id] = session_config

        return creds

    def _to_credentials_response(self, creds: TemporaryCredentials) -> Credentials:
        """Convert TemporaryCredentials to API response format."""
        return Credentials(
            AccessKeyId=creds.access_key_id,
            SecretAccessKey=creds.secret_access_key,
            SessionToken=creds.session_token,
            Expiration=creds.expiration,
        )

    def _lookup_assumed_role_credentials(
        self, access_key_id: str, account_id: str, region: str
    ) -> TemporaryCredentials | None:
        store = self._get_store(account_id, region)
        creds = store.credentials.get(access_key_id)
        if creds and creds.is_expired():
            del store.credentials[access_key_id]
            return None
        return creds

    # TODO use iam stores when service is internalized
    def _lookup_user_by_access_key_id(
        self, access_key_id: str, account_id, partition
    ) -> MotoUser | None:
        backend = iam_backends[account_id][partition]
        return backend.get_user_from_access_key_id(access_key_id)

    def get_caller_identity(self, context: RequestContext, **kwargs) -> GetCallerIdentityResponse:
        """Get the identity of the caller."""
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)

        # Check if this is a temporary credential
        if access_key_id:
            temp_creds = self._lookup_assumed_role_credentials(
                access_key_id, context.account_id, context.region
            )
            if temp_creds:
                return GetCallerIdentityResponse(
                    UserId=temp_creds.user_id,
                    Account=temp_creds.account_id,
                    Arn=temp_creds.arn,
                )

            user = self._lookup_user_by_access_key_id(
                access_key_id, context.account_id, context.partition
            )
            if user:
                return GetCallerIdentityResponse(
                    UserId=user.id,
                    Account=user.account_id,
                    Arn=user.arn,
                )

        # Default: return root identity
        return GetCallerIdentityResponse(
            UserId=context.account_id,
            Account=context.account_id,
            Arn=f"arn:{context.partition}:iam::{context.account_id}:root",
        )

    def get_session_token(
        self,
        context: RequestContext,
        duration_seconds: durationSecondsType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        **kwargs,
    ) -> GetSessionTokenResponse:
        """Get temporary credentials for the current user."""
        duration = duration_seconds or DEFAULT_SESSION_DURATION
        if duration < MIN_SESSION_DURATION:
            duration = MIN_SESSION_DURATION

        # Create credentials for the current caller
        arn = f"arn:{context.partition}:iam::{context.account_id}:root"
        user_id = context.account_id

        creds = self._create_credentials(
            account_id=context.account_id,
            arn=arn,
            user_id=user_id,
            duration_seconds=duration,
        )

        return GetSessionTokenResponse(
            Credentials=self._to_credentials_response(creds),
        )

    def get_federation_token(
        self,
        context: RequestContext,
        name: userNameType,
        policy: sessionPolicyDocumentType = None,
        policy_arns: policyDescriptorListType = None,
        duration_seconds: durationSecondsType = None,
        tags: tagListType = None,
        **kwargs,
    ) -> GetFederationTokenResponse:
        """Get temporary credentials for a federated user."""
        # Validate policy length
        if policy and len(policy) > MAX_FEDERATION_TOKEN_POLICY_LENGTH:
            raise ValidationError(
                f"1 validation error detected: Value at 'policy' failed to satisfy constraint: "
                f"Member must have length less than or equal to {MAX_FEDERATION_TOKEN_POLICY_LENGTH}"
            )

        duration = duration_seconds or DEFAULT_SESSION_DURATION
        if duration < MIN_SESSION_DURATION:
            duration = MIN_SESSION_DURATION

        # Create federated user ARN
        federated_user_id = f"{context.account_id}:{name}"
        arn = f"arn:{context.partition}:sts::{context.account_id}:federated-user/{name}"

        creds = self._create_credentials(
            account_id=context.account_id,
            arn=arn,
            user_id=federated_user_id,
            duration_seconds=duration,
        )

        return GetFederationTokenResponse(
            Credentials=self._to_credentials_response(creds),
            FederatedUser=FederatedUser(
                FederatedUserId=federated_user_id,
                Arn=arn,
            ),
        )

    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: unrestrictedSessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
        provided_contexts: ProvidedContextsListType = None,
        **kwargs,
    ) -> AssumeRoleResponse:
        """Assume a role and return temporary credentials."""
        # Validate role ARN format
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        # Validate session name format
        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        # Validate session name length
        if len(role_session_name) > MAX_ROLE_SESSION_NAME_LENGTH:
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must have length less than or equal to {MAX_ROLE_SESSION_NAME_LENGTH}"
            )

        # Get target account from role ARN
        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id

        # Get the caller's existing session config for tag propagation
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        store = self._get_store(target_account_id, "us-east-1")
        existing_session_config = store.sessions.get(access_key_id, {}) if access_key_id else {}

        # Process tags
        session_config = None
        if tags:
            tag_keys = {tag["Key"].lower() for tag in tags}

            # Check for duplicate tag keys (case-insensitive)
            if len(tag_keys) < len(tags):
                raise InvalidParameterValueError(
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                )

            # Check if trying to override transitive tags
            if existing_session_config:
                existing_transitive = set(existing_session_config.get("transitive_tags", []))
                if existing_transitive.intersection(tag_keys):
                    raise InvalidParameterValueError(
                        "One of the specified transitive tag keys can't be set because it "
                        "conflicts with a transitive tag key from the calling session."
                    )

            # Validate transitive tag keys are in the provided tags
            if transitive_tag_keys:
                transitive_set = {key.lower() for key in transitive_tag_keys}
                if not transitive_set <= tag_keys:
                    raise InvalidParameterValueError(
                        "The specified transitive tag key must be included in the requested tags."
                    )

            # Build session config
            transformed_tags = {tag["Key"].lower(): tag for tag in tags}
            transitive_list = [key.lower() for key in (transitive_tag_keys or [])]

            # Propagate transitive tags from existing session
            if existing_session_config:
                for tag_key in existing_session_config.get("transitive_tags", []):
                    if tag_key in existing_session_config.get("tags", {}):
                        transformed_tags[tag_key] = existing_session_config["tags"][tag_key]
                transitive_list.extend(existing_session_config.get("transitive_tags", []))

            session_config = SessionConfig(
                tags=transformed_tags,
                transitive_tags=transitive_list,
                iam_context={},
            )

        # Extract role name from ARN
        role_resource = extract_resource_from_arn(role_arn)
        role_name = role_resource.split("/")[-1] if role_resource else "unknown"

        # Generate role ID and assumed role ARN
        role_id = generate_role_id()
        if role := self._get_role_from_arn(role_arn):
            role_id = role["RoleId"]
        assumed_role_id = f"{role_id}:{role_session_name}"
        assumed_role_arn = f"arn:{context.partition}:sts::{target_account_id}:assumed-role/{role_name}/{role_session_name}"

        duration = duration_seconds or DEFAULT_SESSION_DURATION
        if duration < MIN_SESSION_DURATION:
            duration = MIN_SESSION_DURATION

        creds = self._create_credentials(
            account_id=target_account_id,
            arn=assumed_role_arn,
            user_id=assumed_role_id,
            duration_seconds=duration,
            session_config=session_config,
            source_identity=source_identity,
        )

        return AssumeRoleResponse(
            Credentials=self._to_credentials_response(creds),
            AssumedRoleUser=AssumedRoleUser(
                AssumedRoleId=assumed_role_id,
                Arn=assumed_role_arn,
            ),
            SourceIdentity=source_identity,
        )

    def assume_role_with_web_identity(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        web_identity_token: clientTokenType,
        provider_id: urlType = None,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        **kwargs,
    ) -> AssumeRoleWithWebIdentityResponse:
        """Assume a role using a web identity token."""
        # Validate role ARN format
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        # Validate session name
        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id

        # Extract role name from ARN
        role_resource = extract_resource_from_arn(role_arn)
        role_name = role_resource.split("/")[-1] if role_resource else "unknown"

        # Generate assumed role info
        role_id = generate_role_id()
        if role := self._get_role_from_arn(role_arn):
            role_id = role["RoleId"]
        assumed_role_id = f"{role_id}:{role_session_name}"
        assumed_role_arn = f"arn:{context.partition}:sts::{target_account_id}:assumed-role/{role_name}/{role_session_name}"

        duration = duration_seconds or DEFAULT_SESSION_DURATION
        if duration < MIN_SESSION_DURATION:
            duration = MIN_SESSION_DURATION

        creds = self._create_credentials(
            account_id=target_account_id,
            arn=assumed_role_arn,
            user_id=assumed_role_id,
            duration_seconds=duration,
        )

        return AssumeRoleWithWebIdentityResponse(
            Credentials=self._to_credentials_response(creds),
            AssumedRoleUser=AssumedRoleUser(
                AssumedRoleId=assumed_role_id,
                Arn=assumed_role_arn,
            ),
            Provider=provider_id,
        )

    def assume_role_with_saml(
        self,
        context: RequestContext,
        role_arn: arnType,
        principal_arn: arnType,
        saml_assertion: SAMLAssertionType,
        policy_arns: policyDescriptorListType = None,
        policy: sessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        **kwargs,
    ) -> AssumeRoleWithSAMLResponse:
        """Assume a role using a SAML assertion."""
        # Decode and parse SAML assertion
        try:
            decoded_assertion = base64.b64decode(saml_assertion).decode("utf-8")
            root = ElementTree.fromstring(decoded_assertion)
        except Exception as e:
            LOG.warning("Failed to parse SAML assertion: %s", e)
            raise ValidationError("Invalid SAML assertion")

        # Extract session name from SAML attributes
        session_name = None
        session_duration = None

        # Try to find attributes in the SAML assertion
        # Handle different namespace prefixes
        for attr in root.iter():
            if "Attribute" in attr.tag:
                name = attr.get("Name", "")
                if "RoleSessionName" in name:
                    for value in attr:
                        if "AttributeValue" in value.tag:
                            session_name = (value.text or "").strip()
                            break
                elif "SessionDuration" in name:
                    for value in attr:
                        if "AttributeValue" in value.tag:
                            try:
                                session_duration = int((value.text or "").strip())
                            except ValueError:
                                pass
                            break

        if not session_name:
            session_name = "SAMLSession"

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id

        # Extract role name from ARN
        role_resource = extract_resource_from_arn(role_arn)
        role_name = role_resource.split("/")[-1] if role_resource else "unknown"

        # Generate assumed role info
        role_id = generate_role_id()
        if role := self._get_role_from_arn(role_arn):
            role_id = role["RoleId"]
        assumed_role_id = f"{role_id}:{session_name}"
        assumed_role_arn = f"arn:{context.partition}:sts::{target_account_id}:assumed-role/{role_name}/{session_name}"

        # Use duration from SAML assertion, parameter, or default
        duration = duration_seconds or session_duration or DEFAULT_SESSION_DURATION
        if duration < MIN_SESSION_DURATION:
            duration = MIN_SESSION_DURATION

        creds = self._create_credentials(
            account_id=target_account_id,
            arn=assumed_role_arn,
            user_id=assumed_role_id,
            duration_seconds=duration,
        )

        return AssumeRoleWithSAMLResponse(
            Credentials=self._to_credentials_response(creds),
            AssumedRoleUser=AssumedRoleUser(
                AssumedRoleId=assumed_role_id,
                Arn=assumed_role_arn,
            ),
        )

    def get_access_key_info(
        self, context: RequestContext, access_key_id: str, **kwargs
    ) -> GetAccessKeyInfoResponse:
        """Get the account ID for an access key."""
        # Check if it's a temporary credential we issued
        creds = self._lookup_credentials(access_key_id)
        if creds:
            return GetAccessKeyInfoResponse(Account=creds.account_id)

        # For permanent access keys (AKIA prefix), extract account from the key
        # In LocalStack, we often encode the account ID in the access key
        if access_key_id.startswith("AKIA"):
            # Default to context account if we can't determine
            return GetAccessKeyInfoResponse(Account=context.account_id)

        # Default response
        return GetAccessKeyInfoResponse(Account=context.account_id)
