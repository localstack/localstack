import base64
import copy
import datetime
import logging
import os
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.kms import (
    AlgorithmSpec,
    AlreadyExistsException,
    CancelKeyDeletionRequest,
    CancelKeyDeletionResponse,
    CiphertextType,
    CreateAliasRequest,
    CreateGrantRequest,
    CreateGrantResponse,
    CreateKeyRequest,
    CreateKeyResponse,
    DataKeyPairSpec,
    DateType,
    DecryptResponse,
    DeleteAliasRequest,
    DescribeKeyRequest,
    DescribeKeyResponse,
    DisabledException,
    DisableKeyRequest,
    DisableKeyRotationRequest,
    EnableKeyRequest,
    EncryptionAlgorithmSpec,
    EncryptionContextType,
    EncryptResponse,
    ExpirationModelType,
    GenerateDataKeyPairResponse,
    GenerateDataKeyPairWithoutPlaintextResponse,
    GenerateDataKeyRequest,
    GenerateDataKeyResponse,
    GenerateDataKeyWithoutPlaintextRequest,
    GenerateDataKeyWithoutPlaintextResponse,
    GenerateMacRequest,
    GenerateMacResponse,
    GenerateRandomRequest,
    GenerateRandomResponse,
    GetKeyPolicyRequest,
    GetKeyPolicyResponse,
    GetKeyRotationStatusRequest,
    GetKeyRotationStatusResponse,
    GetParametersForImportResponse,
    GetPublicKeyResponse,
    GrantIdType,
    GrantTokenList,
    GrantTokenType,
    ImportKeyMaterialResponse,
    IncorrectKeyException,
    InvalidCiphertextException,
    InvalidGrantIdException,
    InvalidKeyUsageException,
    KeyIdType,
    KeySpec,
    KeyState,
    KmsApi,
    KMSInvalidStateException,
    LimitType,
    ListAliasesResponse,
    ListGrantsRequest,
    ListGrantsResponse,
    ListKeyPoliciesRequest,
    ListKeyPoliciesResponse,
    ListKeysRequest,
    ListKeysResponse,
    ListResourceTagsRequest,
    ListResourceTagsResponse,
    MacAlgorithmSpec,
    MarkerType,
    NotFoundException,
    NullableBooleanType,
    PlaintextType,
    PrincipalIdType,
    PutKeyPolicyRequest,
    RecipientInfo,
    ReEncryptResponse,
    ReplicateKeyRequest,
    ReplicateKeyResponse,
    ScheduleKeyDeletionRequest,
    ScheduleKeyDeletionResponse,
    SignRequest,
    SignResponse,
    TagResourceRequest,
    UnsupportedOperationException,
    UntagResourceRequest,
    UpdateAliasRequest,
    UpdateKeyDescriptionRequest,
    VerifyMacRequest,
    VerifyMacResponse,
    VerifyRequest,
    VerifyResponse,
    WrappingKeySpec,
)
from localstack.services.kms.exceptions import ValidationException
from localstack.services.kms.models import (
    MULTI_REGION_PATTERN,
    PATTERN_UUID,
    RESERVED_ALIASES,
    KeyImportState,
    KmsAlias,
    KmsCryptoKey,
    KmsGrant,
    KmsKey,
    KmsStore,
    deserialize_ciphertext_blob,
    kms_stores,
)
from localstack.services.kms.utils import is_valid_key_arn, parse_key_arn, validate_alias_name
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import kms_alias_arn, parse_arn
from localstack.utils.collections import PaginatedList
from localstack.utils.common import select_attributes
from localstack.utils.strings import short_uid, to_bytes, to_str

LOG = logging.getLogger(__name__)

# valid operations
VALID_OPERATIONS = [
    "CreateKey",
    "Decrypt",
    "Encrypt",
    "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext",
    "ReEncryptFrom",
    "ReEncryptTo",
    "Sign",
    "Verify",
    "GetPublicKey",
    "CreateGrant",
    "RetireGrant",
    "DescribeKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
]


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message)


# For all operations constraints for states of keys are based on
# https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
class KmsProvider(KmsApi, ServiceLifecycleHook):
    """
    The LocalStack Key Management Service (KMS) provider.

    Cross-account access is supported by following operations where key ID belonging
    to another account can be used with the key ARN.
    - CreateGrant
    - DescribeKey
    - GetKeyRotationStatus
    - GetPublicKey
    - ListGrants
    - RetireGrant
    - RevokeGrant
    - Decrypt
    - Encrypt
    - GenerateDataKey
    - GenerateDataKeyPair
    - GenerateDataKeyPairWithoutPlaintext
    - GenerateDataKeyWithoutPlaintext
    - GenerateMac
    - ReEncrypt
    - Sign
    - Verify
    - VerifyMac
    """

    #
    # Helpers
    #

    @staticmethod
    def _get_store(account_id: str, region_name: str) -> KmsStore:
        return kms_stores[account_id][region_name]

    @staticmethod
    def _create_kms_alias(account_id: str, region_name: str, request: CreateAliasRequest):
        store = kms_stores[account_id][region_name]
        alias = KmsAlias(request, account_id, region_name)
        alias_name = request.get("AliasName")
        store.aliases[alias_name] = alias

    @staticmethod
    def _create_kms_key(
        account_id: str, region_name: str, request: CreateKeyRequest = None
    ) -> KmsKey:
        store = kms_stores[account_id][region_name]
        key = KmsKey(request, account_id, region_name)
        key_id = key.metadata.get("KeyId")
        store.keys[key_id] = key
        return key

    @staticmethod
    def _get_key_id_from_any_id(account_id: str, region_name: str, some_id: str) -> str:
        """
        Resolve a KMS key ID by using one of the following identifiers:
        - key ID
        - key ARN
        - key alias
        - key alias ARN
        """
        alias_name = None
        key_id = None
        key_arn = None

        if some_id.startswith("arn:"):
            if ":alias/" in some_id:
                alias_arn = some_id
                alias_name = "alias/" + alias_arn.split(":alias/")[1]
            elif ":key/" in some_id:
                key_arn = some_id
                key_id = key_arn.split(":key/")[1]
                parsed_arn = parse_arn(key_arn)
                if parsed_arn["region"] != region_name:
                    raise NotFoundException(f"Invalid arn {parsed_arn['region']}")
            else:
                raise ValueError(
                    f"Supplied value of {some_id} is an ARN, but neither of a KMS key nor of a KMS key "
                    f"alias"
                )
        elif some_id.startswith("alias/"):
            alias_name = some_id
        else:
            key_id = some_id

        store = kms_stores[account_id][region_name]

        if alias_name:
            KmsProvider._create_alias_if_reserved_and_not_exists(
                account_id,
                region_name,
                alias_name,
            )
            if alias_name not in store.aliases:
                raise NotFoundException(f"Unable to find KMS alias with name {alias_name}")
            key_id = store.aliases[alias_name].metadata["TargetKeyId"]

        # regular KeyId are UUID, and MultiRegion keys starts with 'mrk-' and 32 hex chars
        if not PATTERN_UUID.match(key_id) and not MULTI_REGION_PATTERN.match(key_id):
            raise NotFoundException(f"Invalid keyId {key_id}")

        if key_id not in store.keys:
            if not key_arn:
                key_arn = f"arn:aws:kms:{region_name}:{account_id}:key/{key_id}"
            raise NotFoundException(f"Key '{key_arn}' does not exist")

        return key_id

    @staticmethod
    def _create_alias_if_reserved_and_not_exists(
        account_id: str, region_name: str, alias_name: str
    ):
        store = kms_stores[account_id][region_name]
        if alias_name not in RESERVED_ALIASES or alias_name in store.aliases:
            return
        create_key_request = {}
        key_id = KmsProvider._create_kms_key(
            account_id,
            region_name,
            create_key_request,
        ).metadata.get("KeyId")
        create_alias_request = CreateAliasRequest(AliasName=alias_name, TargetKeyId=key_id)
        KmsProvider._create_kms_alias(account_id, region_name, create_alias_request)

    # While in AWS keys have more than Enabled, Disabled and PendingDeletion states, we currently only model these 3
    # in LocalStack, so this function is limited to them.
    #
    # The current default values are based on most of the operations working in AWS with enabled keys, but failing with
    # disabled and those pending deletion.
    #
    # If we decide to use the other states as well, we might want to come up with a better key state validation per
    # operation. Can consult this page for what states are supported by various operations:
    # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
    @staticmethod
    def _get_kms_key(
        account_id: str,
        region_name: str,
        any_type_of_key_id: str,
        any_key_state_allowed: bool = False,
        enabled_key_allowed: bool = True,
        disabled_key_allowed: bool = False,
        pending_deletion_key_allowed: bool = False,
    ) -> KmsKey:
        store = kms_stores[account_id][region_name]

        if any_key_state_allowed:
            enabled_key_allowed = True
            disabled_key_allowed = True
            pending_deletion_key_allowed = True
        if not (enabled_key_allowed or disabled_key_allowed or pending_deletion_key_allowed):
            raise ValueError("A key is requested, but all possible key states are prohibited")

        key_id = KmsProvider._get_key_id_from_any_id(account_id, region_name, any_type_of_key_id)
        key = store.keys[key_id]

        if not disabled_key_allowed and key.metadata.get("KeyState") == "Disabled":
            raise DisabledException(f"{key.metadata.get('Arn')} is disabled.")
        if not pending_deletion_key_allowed and key.metadata.get("KeyState") == "PendingDeletion":
            raise KMSInvalidStateException(f"{key.metadata.get('Arn')} is pending deletion.")
        if not enabled_key_allowed and key.metadata.get("KeyState") == "Enabled":
            raise KMSInvalidStateException(
                f"{key.metadata.get('Arn')} is enabled, but the operation doesn't support "
                f"such a state"
            )
        return store.keys[key_id]

    @staticmethod
    def _get_kms_alias(account_id: str, region_name: str, alias_name_or_arn: str) -> KmsAlias:
        store = kms_stores[account_id][region_name]

        if not alias_name_or_arn.startswith("arn:"):
            alias_name = alias_name_or_arn
        else:
            if ":alias/" not in alias_name_or_arn:
                raise ValidationException(f"{alias_name_or_arn} is not a valid alias ARN")
            alias_name = "alias/" + alias_name_or_arn.split(":alias/")[1]

        validate_alias_name(alias_name)

        if alias_name not in store.aliases:
            alias_arn = kms_alias_arn(alias_name, account_id, region_name)
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise NotFoundException(f"Alias {alias_arn} is not found.")

        return store.aliases.get(alias_name)

    @staticmethod
    def _parse_key_id(key_id_or_arn: str, context: RequestContext) -> Tuple[str, str, str]:
        """
        Return locator attributes (account ID, region_name, key ID) of a given KMS key.

        If an ARN is provided, this is extracted from it. Otherwise, context data is used.

        :param key_id_or_arn: KMS key ID or ARN
        :param context: request context
        :return: Tuple of account ID, region name and key ID
        """
        if is_valid_key_arn(key_id_or_arn):
            account_id, region_name, key_id = parse_key_arn(key_id_or_arn)
            if region_name != context.region:
                raise NotFoundException(f"Invalid arn {region_name}")
            return account_id, region_name, key_id

        return context.account_id, context.region, key_id_or_arn

    #
    # Operation Handlers
    #

    @handler("CreateKey", expand=False)
    def create_key(
        self,
        context: RequestContext,
        request: CreateKeyRequest = None,
    ) -> CreateKeyResponse:
        key = self._create_kms_key(context.account_id, context.region, request)
        return CreateKeyResponse(KeyMetadata=key.metadata)

    @handler("ScheduleKeyDeletion", expand=False)
    def schedule_key_deletion(
        self, context: RequestContext, request: ScheduleKeyDeletionRequest
    ) -> ScheduleKeyDeletionResponse:
        pending_window = int(request.get("PendingWindowInDays", 30))
        if pending_window < 7 or pending_window > 30:
            raise ValidationException(
                f"PendingWindowInDays should be between 7 and 30, but it is {pending_window}"
            )
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.schedule_key_deletion(pending_window)
        attrs = ["DeletionDate", "KeyId", "KeyState"]
        result = select_attributes(key.metadata, attrs)
        result["PendingWindowInDays"] = pending_window
        return ScheduleKeyDeletionResponse(**result)

    @handler("CancelKeyDeletion", expand=False)
    def cancel_key_deletion(
        self, context: RequestContext, request: CancelKeyDeletionRequest
    ) -> CancelKeyDeletionResponse:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=False,
            pending_deletion_key_allowed=True,
        )
        key.metadata["KeyState"] = KeyState.Disabled
        key.metadata["DeletionDate"] = None
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html#API_CancelKeyDeletion_ResponseElements
        # "The Amazon Resource Name (key ARN) of the KMS key whose deletion is canceled."
        return CancelKeyDeletionResponse(KeyId=key.metadata.get("Arn"))

    @handler("DisableKey", expand=False)
    def disable_key(self, context: RequestContext, request: DisableKeyRequest) -> None:
        # Technically, AWS allows DisableKey for keys that are already disabled.
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.metadata["KeyState"] = KeyState.Disabled
        key.metadata["Enabled"] = False

    @handler("EnableKey", expand=False)
    def enable_key(self, context: RequestContext, request: EnableKeyRequest) -> None:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.metadata["KeyState"] = KeyState.Enabled
        key.metadata["Enabled"] = True

    @handler("ListKeys", expand=False)
    def list_keys(self, context: RequestContext, request: ListKeysRequest) -> ListKeysResponse:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html#API_ListKeys_ResponseSyntax
        # Out of whole KeyMetadata only two fields are present in the response.
        keys_list = PaginatedList(
            [
                {"KeyId": key.metadata["KeyId"], "KeyArn": key.metadata["Arn"]}
                for key in self._get_store(context.account_id, context.region).keys.values()
            ]
        )
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html#API_ListKeys_RequestParameters
        # Regarding the default value of Limit: "If you do not include a value, it defaults to 100."
        page, next_token = keys_list.get_page(
            lambda key_data: key_data.get("KeyId"),
            next_token=request.get("Marker"),
            page_size=request.get("Limit", 100),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListKeysResponse(Keys=page, **kwargs)

    @handler("DescribeKey", expand=False)
    def describe_key(
        self, context: RequestContext, request: DescribeKeyRequest
    ) -> DescribeKeyResponse:
        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id, any_key_state_allowed=True)
        return DescribeKeyResponse(KeyMetadata=key.metadata)

    @handler("ReplicateKey", expand=False)
    def replicate_key(
        self, context: RequestContext, request: ReplicateKeyRequest
    ) -> ReplicateKeyResponse:
        key = self._get_kms_key(context.account_id, context.region, request.get("KeyId"))
        key_id = key.metadata.get("KeyId")
        if not key.metadata.get("MultiRegion"):
            raise UnsupportedOperationException(
                f"Unable to replicate a non-MultiRegion key {key_id}"
            )
        replica_region = request.get("ReplicaRegion")
        replicate_to_store = kms_stores[context.account_id][replica_region]
        if key_id in replicate_to_store.keys:
            raise AlreadyExistsException(
                f"Unable to replicate key {key_id} to region {replica_region}, as the key "
                f"already exist there"
            )
        replica_key = copy.deepcopy(key)
        replica_key.metadata["Description"] = request.get("Description", "")
        # Multiregion keys have the same key ID for all replicas, but ARNs differ, as they include actual regions of
        # replicas.
        replica_key.calculate_and_set_arn(context.account_id, replica_region)
        replicate_to_store.keys[key_id] = replica_key
        return ReplicateKeyResponse(ReplicaKeyMetadata=replica_key.metadata)

    @handler("UpdateKeyDescription", expand=False)
    def update_key_description(
        self, context: RequestContext, request: UpdateKeyDescriptionRequest
    ) -> None:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.metadata["Description"] = request.get("Description")

    @handler("CreateGrant", expand=False)
    def create_grant(
        self, context: RequestContext, request: CreateGrantRequest
    ) -> CreateGrantResponse:
        key_account_id, key_region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(key_account_id, key_region_name, key_id)

        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key_id = key.metadata.get("KeyId")
        request["KeyId"] = key_id
        self._validate_grant_request(request)
        grant_name = request.get("Name")

        store = self._get_store(context.account_id, context.region)
        if grant_name and (grant_name, key_id) in store.grant_names:
            grant = store.grants[store.grant_names[(grant_name, key_id)]]
        else:
            grant = KmsGrant(request, context.account_id, context.region)
            grant_id = grant.metadata["GrantId"]
            store.grants[grant_id] = grant
            if grant_name:
                store.grant_names[(grant_name, key_id)] = grant_id
            store.grant_tokens[grant.token] = grant_id

        # At the moment we do not support multiple GrantTokens for grant creation request. Instead, we always use
        # the same token. For the reference, AWS documentation says:
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html#API_CreateGrant_RequestParameters
        # "The returned grant token is unique with every CreateGrant request, even when a duplicate GrantId is
        # returned". "A duplicate GrantId" refers to the idempotency of grant creation requests - if a request has
        # "Name" field, and if such name already belongs to a previously created grant, no new grant gets created
        # and the existing grant with the name is returned.
        return CreateGrantResponse(GrantId=grant.metadata["GrantId"], GrantToken=grant.token)

    @handler("ListGrants", expand=False)
    def list_grants(
        self, context: RequestContext, request: ListGrantsRequest
    ) -> ListGrantsResponse:
        if not request.get("KeyId"):
            raise ValidationError("Required input parameter KeyId not specified")
        key_account_id, key_region_name, _ = self._parse_key_id(request["KeyId"], context)
        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = self._get_kms_key(
            key_account_id, key_region_name, request.get("KeyId"), any_key_state_allowed=True
        )
        key_id = key.metadata.get("KeyId")

        store = self._get_store(context.account_id, context.region)
        grant_id = request.get("GrantId")
        if grant_id:
            if grant_id not in store.grants:
                raise InvalidGrantIdException()
            return ListGrantsResponse(Grants=[store.grants[grant_id].metadata])

        matching_grants = []
        grantee_principal = request.get("GranteePrincipal")
        for grant in store.grants.values():
            # KeyId is a mandatory field of ListGrants request, so is going to be present.
            _, _, grant_key_id = parse_key_arn(grant.metadata["KeyArn"])
            if grant_key_id != key_id:
                continue
            # GranteePrincipal is a mandatory field for CreateGrant, should be in grants. But it is an optional field
            # for ListGrants, so might not be there.
            if grantee_principal and grant.metadata["GranteePrincipal"] != grantee_principal:
                continue
            matching_grants.append(grant.metadata)

        grants_list = PaginatedList(matching_grants)
        page, next_token = grants_list.get_page(
            lambda grant_data: grant_data.get("GrantId"),
            next_token=request.get("Marker"),
            page_size=request.get("Limit", 50),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}

        return ListGrantsResponse(Grants=page, **kwargs)

    @staticmethod
    def _delete_grant(store: KmsStore, grant_id: str, key_id: str):
        grant = store.grants[grant_id]

        _, _, grant_key_id = parse_key_arn(grant.metadata.get("KeyArn"))
        if key_id != grant_key_id:
            raise ValidationError(f"Invalid KeyId={key_id} specified for grant {grant_id}")

        store.grant_tokens.pop(grant.token)
        store.grant_names.pop((grant.metadata.get("Name"), key_id), None)
        store.grants.pop(grant_id)

    def revoke_grant(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        grant_id: GrantIdType,
        dry_run: NullableBooleanType = None,
    ) -> None:
        # TODO add support for "dry_run"
        key_account_id, key_region_name, key_id = self._parse_key_id(key_id, context)
        key = self._get_kms_key(key_account_id, key_region_name, key_id, any_key_state_allowed=True)
        key_id = key.metadata.get("KeyId")

        store = self._get_store(context.account_id, context.region)

        if grant_id not in store.grants:
            raise InvalidGrantIdException()

        self._delete_grant(store, grant_id, key_id)

    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType = None,
        key_id: KeyIdType = None,
        grant_id: GrantIdType = None,
        dry_run: NullableBooleanType = None,
    ) -> None:
        # TODO add support for "dry_run"
        if not grant_token and (not grant_id or not key_id):
            raise ValidationException("Grant token OR (grant ID, key ID) must be specified")

        if grant_token:
            decoded_token = to_str(base64.b64decode(grant_token))
            grant_account_id, grant_region_name, _ = decoded_token.split(":")
            grant_store = self._get_store(grant_account_id, grant_region_name)

            if grant_token not in grant_store.grant_tokens:
                raise NotFoundException(f"Unable to find grant token {grant_token}")

            grant_id = grant_store.grant_tokens[grant_token]
        else:
            grant_store = self._get_store(context.account_id, context.region)

        if key_id:
            key_account_id, key_region_name, key_id = self._parse_key_id(key_id, context)
            key = self._get_kms_key(
                key_account_id, key_region_name, key_id, any_key_state_allowed=True
            )
            key_id = key.metadata.get("KeyId")
        else:
            _, _, key_id = parse_key_arn(grant_store.grants[grant_id].metadata.get("KeyArn"))

        self._delete_grant(grant_store, grant_id, key_id)

    def list_retirable_grants(
        self,
        context: RequestContext,
        retiring_principal: PrincipalIdType,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListGrantsResponse:
        if not retiring_principal:
            raise ValidationError("Required input parameter 'RetiringPrincipal' not specified")

        matching_grants = [
            grant.metadata
            for grant in self._get_store(context.account_id, context.region).grants.values()
            if grant.metadata.get("RetiringPrincipal") == retiring_principal
        ]
        grants_list = PaginatedList(matching_grants)
        limit = limit or 50
        page, next_token = grants_list.get_page(
            lambda grant_data: grant_data.get("GrantId"),
            next_token=marker,
            page_size=limit,
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}

        return ListGrantsResponse(Grants=page, **kwargs)

    def get_public_key(
        self, context: RequestContext, key_id: KeyIdType, grant_tokens: GrantTokenList = None
    ) -> GetPublicKeyResponse:
        # According to https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html, GetPublicKey is supposed
        # to fail for disabled keys. But it actually doesn't fail in AWS.
        account_id, region_name, key_id = self._parse_key_id(key_id, context)
        key = self._get_kms_key(
            account_id,
            region_name,
            key_id,
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        attrs = [
            "KeySpec",
            "KeyUsage",
            "EncryptionAlgorithms",
            "SigningAlgorithms",
        ]
        result = select_attributes(key.metadata, attrs)
        result["PublicKey"] = key.crypto_key.public_key
        result["KeyId"] = key.metadata["Arn"]
        return GetPublicKeyResponse(**result)

    def _generate_data_key_pair(
        self,
        context: RequestContext,
        key_id: str,
        key_pair_spec: str,
        encryption_context: EncryptionContextType = None,
    ):
        account_id, region_name, key_id = self._parse_key_id(key_id, context)
        key = self._get_kms_key(account_id, region_name, key_id)
        self._validate_key_for_encryption_decryption(context, key)
        crypto_key = KmsCryptoKey(key_pair_spec)
        return {
            "KeyId": key.metadata["Arn"],
            "KeyPairSpec": key_pair_spec,
            "PrivateKeyCiphertextBlob": key.encrypt(crypto_key.private_key, encryption_context),
            "PrivateKeyPlaintext": crypto_key.private_key,
            "PublicKey": crypto_key.public_key,
        }

    @handler("GenerateDataKeyPair")
    def generate_data_key_pair(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        recipient: RecipientInfo = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyPairResponse:
        # TODO add support for "dry_run"
        result = self._generate_data_key_pair(context, key_id, key_pair_spec, encryption_context)
        return GenerateDataKeyPairResponse(**result)

    @handler("GenerateRandom", expand=False)
    def generate_random(
        self, context: RequestContext, request: GenerateRandomRequest
    ) -> GenerateRandomResponse:
        number_of_bytes = request.get("NumberOfBytes")
        if number_of_bytes is None:
            raise ValidationException("NumberOfBytes is required.")
        if number_of_bytes > 1024:
            raise ValidationException(
                f"1 validation error detected: Value '{number_of_bytes}' at 'numberOfBytes' failed "
                "to satisfy constraint: Member must have value less than or equal to 1024"
            )
        if number_of_bytes < 1:
            raise ValidationException(
                f"1 validation error detected: Value '{number_of_bytes}' at 'numberOfBytes' failed "
                "to satisfy constraint: Member must have value greater than or equal to 1"
            )

        byte_string = os.urandom(number_of_bytes)

        return GenerateRandomResponse(Plaintext=byte_string)

    @handler("GenerateDataKeyPairWithoutPlaintext")
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        key_pair_spec: DataKeyPairSpec,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        # TODO add support for "dry_run"
        result = self._generate_data_key_pair(context, key_id, key_pair_spec, encryption_context)
        result.pop("PrivateKeyPlaintext")
        return GenerateDataKeyPairResponse(**result)

    # We currently act on neither on KeySpec setting (which is different from and holds values different then
    # KeySpec for CreateKey) nor on NumberOfBytes. Instead, we generate a key with a key length that is "standard" in
    # LocalStack.
    #
    def _generate_data_key(
        self, context: RequestContext, key_id: str, encryption_context: EncryptionContextType = None
    ):
        account_id, region_name, key_id = self._parse_key_id(key_id, context)
        key = self._get_kms_key(account_id, region_name, key_id)
        # TODO Should also have a validation for the key being a symmetric one.
        self._validate_key_for_encryption_decryption(context, key)
        crypto_key = KmsCryptoKey("SYMMETRIC_DEFAULT")
        return {
            "KeyId": key.metadata["Arn"],
            "Plaintext": crypto_key.key_material,
            "CiphertextBlob": key.encrypt(crypto_key.key_material, encryption_context),
        }

    @handler("GenerateDataKey", expand=False)
    def generate_data_key(
        self, context: RequestContext, request: GenerateDataKeyRequest
    ) -> GenerateDataKeyResponse:
        result = self._generate_data_key(
            context, request.get("KeyId"), request.get("EncryptionContext")
        )
        return GenerateDataKeyResponse(**result)

    @handler("GenerateDataKeyWithoutPlaintext", expand=False)
    def generate_data_key_without_plaintext(
        self, context: RequestContext, request: GenerateDataKeyWithoutPlaintextRequest
    ) -> GenerateDataKeyWithoutPlaintextResponse:
        result = self._generate_data_key(
            context, request.get("KeyId"), request.get("EncryptionContext")
        )
        result.pop("Plaintext")
        return GenerateDataKeyWithoutPlaintextResponse(**result)

    @handler("GenerateMac", expand=False)
    def generate_mac(
        self,
        context: RequestContext,
        request: GenerateMacRequest,
    ) -> GenerateMacResponse:
        msg = request.get("Message")
        self._validate_mac_msg_length(msg)

        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id)

        self._validate_key_for_generate_verify_mac(context, key)

        algorithm = request.get("MacAlgorithm")
        self._validate_mac_algorithm(key, algorithm)

        mac = key.generate_mac(msg, algorithm)

        return GenerateMacResponse(Mac=mac, MacAlgorithm=algorithm, KeyId=key.metadata.get("Arn"))

    @handler("VerifyMac", expand=False)
    def verify_mac(
        self,
        context: RequestContext,
        request: VerifyMacRequest,
    ) -> VerifyMacResponse:
        msg = request.get("Message")
        self._validate_mac_msg_length(msg)

        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id)

        self._validate_key_for_generate_verify_mac(context, key)

        algorithm = request.get("MacAlgorithm")
        self._validate_mac_algorithm(key, algorithm)

        mac_valid = key.verify_mac(msg, request.get("Mac"), algorithm)

        return VerifyMacResponse(
            KeyId=key.metadata.get("Arn"), MacValid=mac_valid, MacAlgorithm=algorithm
        )

    @handler("Sign", expand=False)
    def sign(self, context: RequestContext, request: SignRequest) -> SignResponse:
        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id)

        self._validate_key_for_sign_verify(context, key)

        # TODO Add constraints on KeySpec / SigningAlgorithm pairs:
        #  https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#key-spec-ecc

        signing_algorithm = request.get("SigningAlgorithm")
        signature = key.sign(request.get("Message"), request.get("MessageType"), signing_algorithm)

        result = {
            "KeyId": key.metadata["Arn"],
            "Signature": signature,
            "SigningAlgorithm": signing_algorithm,
        }
        return SignResponse(**result)

    # Currently LocalStack only calculates SHA256 digests no matter what the signing algorithm is.
    @handler("Verify", expand=False)
    def verify(self, context: RequestContext, request: VerifyRequest) -> VerifyResponse:
        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id)

        self._validate_key_for_sign_verify(context, key)

        signing_algorithm = request.get("SigningAlgorithm")
        is_signature_valid = key.verify(
            request.get("Message"),
            request.get("MessageType"),
            signing_algorithm,
            request.get("Signature"),
        )

        result = {
            "KeyId": key.metadata["Arn"],
            "SignatureValid": is_signature_valid,
            "SigningAlgorithm": signing_algorithm,
        }
        return VerifyResponse(**result)

    def re_encrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        destination_key_id: KeyIdType,
        source_encryption_context: EncryptionContextType = None,
        source_key_id: KeyIdType = None,
        destination_encryption_context: EncryptionContextType = None,
        source_encryption_algorithm: EncryptionAlgorithmSpec = None,
        destination_encryption_algorithm: EncryptionAlgorithmSpec = None,
        grant_tokens: GrantTokenList = None,
        dry_run: NullableBooleanType = None,
    ) -> ReEncryptResponse:
        # TODO: when implementing, ensure cross-account support for source_key_id and destination_key_id
        raise NotImplementedError

    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
        dry_run: NullableBooleanType = None,
    ) -> EncryptResponse:
        # TODO add support for "dry_run"
        account_id, region_name, key_id = self._parse_key_id(key_id, context)
        key = self._get_kms_key(account_id, region_name, key_id)
        self._validate_plaintext_length(plaintext)
        self._validate_plaintext_key_type_based(plaintext, key, encryption_algorithm)
        self._validate_key_for_encryption_decryption(context, key)
        self._validate_key_state_not_pending_import(key)

        ciphertext_blob = key.encrypt(plaintext, encryption_context)
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        return EncryptResponse(
            CiphertextBlob=ciphertext_blob,
            KeyId=key.metadata.get("Arn"),
            EncryptionAlgorithm=encryption_algorithm,
        )

    # TODO We currently do not even check encryption_context, while moto does. Should add the corresponding logic later.
    def decrypt(
        self,
        context: RequestContext,
        ciphertext_blob: CiphertextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        key_id: KeyIdType = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
        recipient: RecipientInfo = None,
        dry_run: NullableBooleanType = None,
    ) -> DecryptResponse:
        # In AWS, key_id is only supplied for data encrypted with an asymmetrical algorithm. For symmetrical
        # encryption, key_id is taken from the encrypted data itself.
        # Since LocalStack doesn't currently do asymmetrical encryption, there is a question of modeling here: we
        # currently expect data to be only encrypted with symmetric encryption, so having key_id inside. It might not
        # always be what customers expect.
        try:
            ciphertext = deserialize_ciphertext_blob(ciphertext_blob=ciphertext_blob)
        except Exception:
            raise InvalidCiphertextException(
                "LocalStack is unable to deserialize the ciphertext blob. Perhaps the "
                "blob didn't come from LocalStack"
            )
        account_id, region_name, key_id = self._parse_key_id(key_id or ciphertext.key_id, context)
        key = self._get_kms_key(account_id, region_name, key_id)
        if key.metadata["KeyId"] != ciphertext.key_id:
            raise IncorrectKeyException(
                "The key ID in the request does not identify a CMK that can perform this operation."
            )

        self._validate_key_for_encryption_decryption(context, key)
        self._validate_key_state_not_pending_import(key)

        try:
            plaintext = key.decrypt(ciphertext, encryption_context)
        except InvalidTag:
            raise InvalidCiphertextException()
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        #
        # We return a key ARN instead of KeyId despite the name of the parameter, as this is what AWS does and states
        # in its docs.
        # TODO add support for "recipient"
        #  https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html#API_Decrypt_RequestSyntax
        # TODO add support for "dry_run"
        return DecryptResponse(
            KeyId=key.metadata.get("Arn"),
            Plaintext=plaintext,
            EncryptionAlgorithm=encryption_algorithm,
        )

    def get_parameters_for_import(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        wrapping_algorithm: AlgorithmSpec,
        wrapping_key_spec: WrappingKeySpec,
    ) -> GetParametersForImportResponse:
        store = self._get_store(context.account_id, context.region)
        # KeyId can potentially hold one of multiple different types of key identifiers. get_key finds a key no
        # matter which type of id is used.
        key_to_import_material_to = self._get_kms_key(
            context.account_id,
            context.region,
            key_id,
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        if key_to_import_material_to.metadata.get("Origin") != "EXTERNAL":
            raise UnsupportedOperationException(
                "Key material can only be imported into keys with Origin of EXTERNAL"
            )
        self._validate_key_for_encryption_decryption(context, key_to_import_material_to)
        key_id = key_to_import_material_to.metadata["KeyId"]

        key = KmsKey(CreateKeyRequest(KeySpec=wrapping_key_spec))
        import_token = short_uid()
        import_state = KeyImportState(
            key_id=key_id, import_token=import_token, wrapping_algo=wrapping_algorithm, key=key
        )
        store.imports[import_token] = import_state
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
        # "To import key material, you must use the public key and import token from the same response. These items
        # are valid for 24 hours."
        expiry_date = datetime.datetime.now() + datetime.timedelta(days=100)
        return GetParametersForImportResponse(
            KeyId=key_to_import_material_to.metadata["Arn"],
            ImportToken=to_bytes(import_state.import_token),
            PublicKey=import_state.key.crypto_key.public_key,
            ParametersValidTo=expiry_date,
        )

    def import_key_material(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        import_token: CiphertextType,
        encrypted_key_material: CiphertextType,
        valid_to: DateType = None,
        expiration_model: ExpirationModelType = None,
    ) -> ImportKeyMaterialResponse:
        store = self._get_store(context.account_id, context.region)
        import_token = to_str(import_token)
        import_state = store.imports.get(import_token)
        if not import_state:
            raise NotFoundException(f"Unable to find key import token '{import_token}'")
        key_to_import_material_to = self._get_kms_key(
            context.account_id,
            context.region,
            key_id,
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        self._validate_key_for_encryption_decryption(context, key_to_import_material_to)

        if import_state.wrapping_algo == AlgorithmSpec.RSAES_PKCS1_V1_5:
            decrypt_padding = padding.PKCS1v15()
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_1:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)
        elif import_state.wrapping_algo == AlgorithmSpec.RSAES_OAEP_SHA_256:
            decrypt_padding = padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
        else:
            raise KMSInvalidStateException(
                f"Unsupported padding, requested wrapping algorithm:'{import_state.wrapping_algo}'"
            )

        # TODO check if there was already a key imported for this kms key
        # if so, it has to be identical. We cannot change keys by reimporting after deletion/expiry
        key_material = import_state.key.crypto_key.key.decrypt(
            encrypted_key_material, decrypt_padding
        )
        if expiration_model:
            key_to_import_material_to.metadata["ExpirationModel"] = expiration_model
        else:
            key_to_import_material_to.metadata[
                "ExpirationModel"
            ] = ExpirationModelType.KEY_MATERIAL_EXPIRES
        if (
            key_to_import_material_to.metadata["ExpirationModel"]
            == ExpirationModelType.KEY_MATERIAL_EXPIRES
            and not valid_to
        ):
            raise ValidationException(
                "A validTo date must be set if the ExpirationModel is KEY_MATERIAL_EXPIRES"
            )
        # TODO actually set validTo and make the key expire
        key_to_import_material_to.crypto_key.key_material = key_material
        key_to_import_material_to.metadata["Enabled"] = True
        key_to_import_material_to.metadata["KeyState"] = KeyState.Enabled
        return ImportKeyMaterialResponse()

    def delete_imported_key_material(self, context: RequestContext, key_id: KeyIdType) -> None:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            key_id,
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.crypto_key.key_material = None
        key.metadata["Enabled"] = False
        key.metadata["KeyState"] = KeyState.PendingImport
        key.metadata.pop("ExpirationModel", None)

    @handler("CreateAlias", expand=False)
    def create_alias(self, context: RequestContext, request: CreateAliasRequest) -> None:
        store = self._get_store(context.account_id, context.region)
        alias_name = request["AliasName"]
        validate_alias_name(alias_name)
        if alias_name in store.aliases:
            alias_arn = store.aliases.get(alias_name).metadata["AliasArn"]
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise AlreadyExistsException(f"An alias with the name {alias_arn} already exists")
        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("TargetKeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        request["TargetKeyId"] = key.metadata.get("KeyId")
        self._create_kms_alias(context.account_id, context.region, request)

    @handler("DeleteAlias", expand=False)
    def delete_alias(self, context: RequestContext, request: DeleteAliasRequest) -> None:
        # We do not check the state of the key, as, according to AWS docs, all key states, that are possible in
        # LocalStack, are supported by this operation.
        store = self._get_store(context.account_id, context.region)
        alias_name = request["AliasName"]
        if alias_name not in store.aliases:
            alias_arn = kms_alias_arn(request["AliasName"], context.account_id, context.region)
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise NotFoundException(f"Alias {alias_arn} is not found")
        store.aliases.pop(alias_name, None)

    @handler("UpdateAlias", expand=False)
    def update_alias(self, context: RequestContext, request: UpdateAliasRequest) -> None:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the source KMS key is pending deletion, the command succeeds. If the destination KMS key is pending
        # deletion, the command fails with error: KMSInvalidStateException : <key ARN> is pending deletion."
        # Also disabled keys are accepted for this operation (see the table on that page).
        #
        # As such, we do not care about the state of the source key, but check the destination one.

        alias_name = request["AliasName"]
        # This API, per AWS docs, accepts only names, not ARNs.
        validate_alias_name(alias_name)
        alias = self._get_kms_alias(context.account_id, context.region, alias_name)
        key_id = request["TargetKeyId"]
        # Don't care about the key itself, just want to validate its state.
        self._get_kms_key(
            context.account_id,
            context.region,
            key_id,
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        alias.metadata["TargetKeyId"] = key_id
        alias.update_date_of_last_update()

    @handler("ListAliases")
    def list_aliases(
        self,
        context: RequestContext,
        key_id: KeyIdType = None,
        limit: LimitType = None,
        marker: MarkerType = None,
    ) -> ListAliasesResponse:
        store = self._get_store(context.account_id, context.region)
        if key_id:
            # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
            # matter which type of id is used.
            key = self._get_kms_key(
                context.account_id, context.region, key_id, any_key_state_allowed=True
            )
            key_id = key.metadata.get("KeyId")

        matching_aliases = []
        for alias in store.aliases.values():
            if key_id and alias.metadata["TargetKeyId"] != key_id:
                continue
            matching_aliases.append(alias.metadata)
        aliases_list = PaginatedList(matching_aliases)
        limit = limit or 100
        page, next_token = aliases_list.get_page(
            lambda alias_metadata: alias_metadata.get("AliasName"),
            next_token=marker,
            page_size=limit,
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListAliasesResponse(Aliases=page, **kwargs)

    @handler("GetKeyRotationStatus", expand=False)
    def get_key_rotation_status(
        self, context: RequestContext, request: GetKeyRotationStatusRequest
    ) -> GetKeyRotationStatusResponse:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the KMS key has imported key material or is in a custom key store: UnsupportedOperationException."
        # We do not model that here, though.
        account_id, region_name, key_id = self._parse_key_id(request["KeyId"], context)
        key = self._get_kms_key(account_id, region_name, key_id, any_key_state_allowed=True)
        return GetKeyRotationStatusResponse(KeyRotationEnabled=key.is_key_rotation_enabled)

    @handler("DisableKeyRotation", expand=False)
    def disable_key_rotation(
        self, context: RequestContext, request: DisableKeyRotationRequest
    ) -> None:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the KMS key has imported key material or is in a custom key store: UnsupportedOperationException."
        # We do not model that here, though.
        key = self._get_kms_key(context.account_id, context.region, request.get("KeyId"))
        key.is_key_rotation_enabled = False

    @handler("EnableKeyRotation", expand=False)
    def enable_key_rotation(
        self, context: RequestContext, request: DisableKeyRotationRequest
    ) -> None:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the KMS key has imported key material or is in a custom key store: UnsupportedOperationException."
        # We do not model that here, though.
        key = self._get_kms_key(context.account_id, context.region, request.get("KeyId"))
        key.is_key_rotation_enabled = True

    @handler("ListKeyPolicies", expand=False)
    def list_key_policies(
        self, context: RequestContext, request: ListKeyPoliciesRequest
    ) -> ListKeyPoliciesResponse:
        # We just care if the key exists. The response, by AWS specifications, is the same for all keys, as the only
        # supported policy is "default":
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyPolicies.html#API_ListKeyPolicies_ResponseElements
        self._get_kms_key(
            context.account_id, context.region, request.get("KeyId"), any_key_state_allowed=True
        )
        return ListKeyPoliciesResponse(PolicyNames=["default"], Truncated=False)

    @handler("PutKeyPolicy", expand=False)
    def put_key_policy(self, context: RequestContext, request: PutKeyPolicyRequest) -> None:
        key = self._get_kms_key(
            context.account_id, context.region, request.get("KeyId"), any_key_state_allowed=True
        )
        if request.get("PolicyName") != "default":
            raise UnsupportedOperationException("Only default policy is supported")
        key.policy = request.get("Policy")

    @handler("GetKeyPolicy", expand=False)
    def get_key_policy(
        self, context: RequestContext, request: GetKeyPolicyRequest
    ) -> GetKeyPolicyResponse:
        key = self._get_kms_key(
            context.account_id, context.region, request.get("KeyId"), any_key_state_allowed=True
        )
        if request.get("PolicyName") != "default":
            raise NotFoundException("No such policy exists")
        return GetKeyPolicyResponse(Policy=key.policy)

    @handler("ListResourceTags", expand=False)
    def list_resource_tags(
        self, context: RequestContext, request: ListResourceTagsRequest
    ) -> ListResourceTagsResponse:
        key = self._get_kms_key(
            context.account_id, context.region, request.get("KeyId"), any_key_state_allowed=True
        )
        keys_list = PaginatedList(
            [{"TagKey": tag_key, "TagValue": tag_value} for tag_key, tag_value in key.tags.items()]
        )
        page, next_token = keys_list.get_page(
            lambda tag: tag.get("TagKey"),
            next_token=request.get("Marker"),
            page_size=request.get("Limit", 50),
        )
        kwargs = {"NextMarker": next_token, "Truncated": True} if next_token else {}
        return ListResourceTagsResponse(Tags=page, **kwargs)

    @handler("TagResource", expand=False)
    def tag_resource(self, context: RequestContext, request: TagResourceRequest) -> None:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        key.add_tags(request.get("Tags"))

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: UntagResourceRequest) -> None:
        key = self._get_kms_key(
            context.account_id,
            context.region,
            request.get("KeyId"),
            enabled_key_allowed=True,
            disabled_key_allowed=True,
        )
        if not request.get("TagKeys"):
            return
        for tag_key in request.get("TagKeys"):
            # AWS doesn't seem to mind removal of a non-existent tag, so we do not raise any exception.
            key.tags.pop(tag_key, None)

    def _validate_key_state_not_pending_import(self, key: KmsKey):
        if key.metadata["KeyState"] == KeyState.PendingImport:
            raise KMSInvalidStateException(f"{key.metadata['Arn']} is pending import.")

    def _validate_key_for_encryption_decryption(self, context: RequestContext, key: KmsKey):
        key_usage = key.metadata["KeyUsage"]
        if key_usage != "ENCRYPT_DECRYPT":
            raise InvalidKeyUsageException(
                f"{key.metadata['Arn']} key usage is {key_usage} which is not valid for {context.operation.name}."
            )

    def _validate_key_for_sign_verify(self, context: RequestContext, key: KmsKey):
        key_usage = key.metadata["KeyUsage"]
        if key_usage != "SIGN_VERIFY":
            raise InvalidKeyUsageException(
                f"{key.metadata['Arn']} key usage is {key_usage} which is not valid for {context.operation.name}."
            )

    def _validate_key_for_generate_verify_mac(self, context: RequestContext, key: KmsKey):
        key_usage = key.metadata["KeyUsage"]
        if key_usage != "GENERATE_VERIFY_MAC":
            raise InvalidKeyUsageException(
                f"{key.metadata['Arn']} key usage is {key_usage} which is not valid for {context.operation.name}."
            )

    def _validate_mac_msg_length(self, msg: bytes):
        if len(msg) > 4096:
            raise ValidationException(
                "1 validation error detected: Value at 'message' failed to satisfy constraint: "
                "Member must have length less than or equal to 4096"
            )

    def _validate_mac_algorithm(self, key: KmsKey, algorithm: str):
        if not hasattr(MacAlgorithmSpec, algorithm):
            raise ValidationException(
                f"1 validation error detected: Value '{algorithm}' at 'macAlgorithm' "
                f"failed to satisfy constraint: Member must satisfy enum value set: "
                f"[HMAC_SHA_384, HMAC_SHA_256, HMAC_SHA_224, HMAC_SHA_512]"
            )

        key_spec = key.metadata["KeySpec"]
        if x := algorithm.split("_"):
            if len(x) == 3 and x[0] + "_" + x[2] != key_spec:
                raise InvalidKeyUsageException(
                    f"Algorithm {algorithm} is incompatible with key spec {key_spec}."
                )

    def _validate_plaintext_length(self, plaintext: bytes):
        if len(plaintext) > 4096:
            raise ValidationException(
                "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: "
                "Member must have length less than or equal to 4096"
            )

    def _validate_grant_request(self, data: Dict):
        if "KeyId" not in data or "GranteePrincipal" not in data or "Operations" not in data:
            raise ValidationError("Grant ID, key ID and grantee principal must be specified")

        for operation in data["Operations"]:
            if operation not in VALID_OPERATIONS:
                raise ValidationError(
                    f"Value {['Operations']} at 'operations' failed to satisfy constraint: Member must satisfy"
                    f" constraint: [Member must satisfy enum value set: {VALID_OPERATIONS}]"
                )

    def _validate_plaintext_key_type_based(
        self,
        plaintext: PlaintextType,
        key: KmsKey,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ):
        # max size values extracted from AWS boto3 documentation
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms/client/encrypt.html
        max_size_bytes = 4096  # max allowed size
        if (
            key.metadata["KeySpec"] == KeySpec.RSA_2048
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1
        ):
            max_size_bytes = 214
        elif (
            key.metadata["KeySpec"] == KeySpec.RSA_2048
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
        ):
            max_size_bytes = 190
        elif (
            key.metadata["KeySpec"] == KeySpec.RSA_3072
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1
        ):
            max_size_bytes = 342
        elif (
            key.metadata["KeySpec"] == KeySpec.RSA_3072
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
        ):
            max_size_bytes = 318
        elif (
            key.metadata["KeySpec"] == KeySpec.RSA_4096
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1
        ):
            max_size_bytes = 470
        elif (
            key.metadata["KeySpec"] == KeySpec.RSA_4096
            and encryption_algorithm == EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256
        ):
            max_size_bytes = 446

        if len(plaintext) > max_size_bytes:
            raise ValidationException(
                f"Algorithm {encryption_algorithm} and key spec {key.metadata['KeySpec']} cannot encrypt data larger than {max_size_bytes} bytes."
            )


# ---------------
# UTIL FUNCTIONS
# ---------------

# Different AWS services have some internal integrations with KMS. Some create keys, that are used to encrypt/decrypt
# customer's data. Such keys can't be created from outside for security reasons. So AWS services use some internal
# APIs to do that. Functions here are supposed to be used by other LocalStack services to have similar integrations
# with KMS in LocalStack. As such, they are supposed to be proper APIs (as in error and security handling),
# just with more features.


def set_key_managed(key_id: str, account_id: str, region_name: str) -> None:
    key = KmsProvider._get_kms_key(account_id, region_name, key_id)
    key.metadata["KeyManager"] = "AWS"
