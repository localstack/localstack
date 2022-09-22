import copy
import datetime
import logging
from typing import Dict

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
    DateType,
    DecryptResponse,
    DeleteAliasRequest,
    DescribeKeyRequest,
    DescribeKeyResponse,
    DisableKeyRequest,
    DisableKeyRotationRequest,
    EnableKeyRequest,
    EncryptionAlgorithmSpec,
    EncryptionContextType,
    EncryptResponse,
    ExpirationModelType,
    GenerateDataKeyPairRequest,
    GenerateDataKeyPairResponse,
    GenerateDataKeyPairWithoutPlaintextRequest,
    GenerateDataKeyPairWithoutPlaintextResponse,
    GenerateDataKeyRequest,
    GenerateDataKeyResponse,
    GenerateDataKeyWithoutPlaintextRequest,
    GenerateDataKeyWithoutPlaintextResponse,
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
    InvalidCiphertextException,
    InvalidGrantIdException,
    InvalidKeyUsageException,
    KeyIdType,
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
    MarkerType,
    NotFoundException,
    PlaintextType,
    PrincipalIdType,
    PutKeyPolicyRequest,
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
    VerifyRequest,
    VerifyResponse,
    WrappingKeySpec,
)
from localstack.services.kms.models import (
    KeyImportState,
    KmsAlias,
    KmsCryptoKey,
    KmsGrant,
    KmsKey,
    KmsStore,
    ValidationException,
    deserialize_ciphertext_blob,
    kms_stores,
    validate_alias_name,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.aws_stack import kms_alias_arn
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
    @staticmethod
    def _get_store(context: RequestContext) -> KmsStore:
        return kms_stores[context.account_id][context.region]

    def _get_key(self, context: RequestContext, key_id: str, **kwargs) -> KmsKey:
        return self._get_store(context).get_key(key_id, **kwargs)

    @handler("CreateKey", expand=False)
    def create_key(
        self,
        context: RequestContext,
        request: CreateKeyRequest = None,
    ) -> CreateKeyResponse:
        key = self._get_store(context).create_key(request, context.account_id, context.region)
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
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
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
        key = self._get_key(
            context,
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
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
        )
        key.metadata["KeyState"] = KeyState.Disabled
        key.metadata["Enabled"] = False

    @handler("EnableKey", expand=False)
    def enable_key(self, context: RequestContext, request: EnableKeyRequest) -> None:
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
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
                for key in self._get_store(context).keys.values()
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
        key = self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
        return DescribeKeyResponse(KeyMetadata=key.metadata)

    @handler("ReplicateKey", expand=False)
    def replicate_key(
        self, context: RequestContext, request: ReplicateKeyRequest
    ) -> ReplicateKeyResponse:
        replicate_from_store = self._get_store(context)
        key = replicate_from_store.get_key(request.get("KeyId"))
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
        if request.get("Description"):
            replica_key.metadata["Description"] = request.get("Description")
        # Multiregion keys have the same key ID for all replicas, but ARNs differ, as they include actual regions of
        # replicas.
        replica_key.calculate_and_set_arn(context.account_id, replica_region)
        replicate_to_store.keys[key_id] = replica_key
        return ReplicateKeyResponse(ReplicaKeyMetadata=replica_key.metadata)

    @handler("UpdateKeyDescription", expand=False)
    def update_key_description(
        self, context: RequestContext, request: UpdateKeyDescriptionRequest
    ) -> None:
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
        )
        key.metadata["Description"] = request.get("Description")

    @handler("CreateGrant", expand=False)
    def create_grant(
        self, context: RequestContext, request: CreateGrantRequest
    ) -> CreateGrantResponse:
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = store.get_key(request.get("KeyId"))
        request["KeyId"] = key.metadata.get("KeyId")
        self._validate_grant_request(request, store)
        grant_name = request.get("Name")
        if grant_name and grant_name in store.grant_names:
            grant = store.grants[store.grant_names[grant_name]]
        else:
            grant = KmsGrant(request)
            grant_id = grant.metadata["GrantId"]
            store.grants[grant_id] = grant
            if grant_name:
                store.grant_names[grant_name] = grant_id
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
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = store.get_key(request.get("KeyId"), any_key_state_allowed=True)
        key_id = key.metadata.get("KeyId")

        grant_id = request.get("GrantId")
        if grant_id:
            if grant_id not in store.grants:
                raise InvalidGrantIdException()
            return ListGrantsResponse(Grants=[store.grants[grant_id].metadata])

        matching_grants = []
        grantee_principal = request.get("GranteePrincipal")
        for grant in store.grants.values():
            # KeyId is a mandatory field of ListGrants request, so is going to be present.
            if grant.metadata["KeyId"] != key_id:
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

    # Honestly, this is a mess in AWS KMS. Hashtag "do we follow specifications that are a pain to customers or do we
    # diverge from AWS and make the life of our customers easier?"
    #
    # Both RetireGrant and RevokeGrant operations delete a grant. The differences between them are described here:
    # https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#grant-delete
    # Essentially:
    # - Permissions to RevokeGrant are controlled through IAM policies or through key policies, while permissions to
    # RetireGrant are controlled by settings inside the grant itself.
    # - A grant to be retired can be specified by its GrantToken or its GrantId/KeyId pair. While revoking grants can
    # only be done with a GrantId/KeyId pair.
    # - For RevokeGrant, KeyId can be either an actual key ID, or an ARN of that key. While for RetireGrant only key
    # ARN is accepted as a KeyId.
    #
    # We currently do not model permissions for retirement and revocation of grants. At least not in KMS,
    # maybe IAM in LocalStack has some modelling though. We also accept both key IDs and key ARNs for both
    # operations. So apart from RevokeGrant not accepting GrantToken parameter, we treat these two operations the same.
    @staticmethod
    def _delete_grant(
        store: KmsStore, grant_id: str = None, key_id: str = None, grant_token: str = None
    ):
        if grant_token:
            if grant_token not in store.grant_tokens:
                raise NotFoundException(f"Unable to find grant token {grant_token}")
            grant_id = store.grant_tokens[grant_token]
            # Do not really care about the key ID if a grant is identified by a token. But since a key has to be
            # validated when a grant is identified by GrantId/KeyId pair, and since we want to use the same code in
            # both cases - when we have a grant token or a GrantId/KeyId pair - have to set key_id.
            key_id = store.grants[grant_id].metadata["KeyId"]

        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = store.get_key(key_id, any_key_state_allowed=True)
        key_id = key.metadata.get("KeyId")

        if grant_id not in store.grants:
            raise InvalidGrantIdException()
        if store.grants[grant_id].metadata["KeyId"] != key_id:
            raise ValidationError(f"Invalid KeyId={key_id} specified for grant {grant_id}")

        grant = store.grants[grant_id]
        # In AWS grants have one or more tokens. But we have a simplified modeling of grants, where they have exactly
        # one token.
        store.grant_tokens.pop(grant.token)
        store.grant_names.pop(grant.metadata.get("Name"), None)
        store.grants.pop(grant_id)

    def revoke_grant(
        self, context: RequestContext, key_id: KeyIdType, grant_id: GrantIdType
    ) -> None:
        self._delete_grant(store=self._get_store(context), grant_id=grant_id, key_id=key_id)

    def retire_grant(
        self,
        context: RequestContext,
        grant_token: GrantTokenType = None,
        key_id: KeyIdType = None,
        grant_id: GrantIdType = None,
    ) -> None:
        if not grant_token and (not grant_id or not key_id):
            raise ValidationException("Grant token OR (grant ID, key ID) must be specified")
        self._delete_grant(
            store=self._get_store(context),
            grant_id=grant_id,
            key_id=key_id,
            grant_token=grant_token,
        )

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
            for grant in self._get_store(context).grants.values()
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
        key = self._get_key(context, key_id, enabled_key_allowed=True, disabled_key_allowed=True)
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

    def _generate_data_key_pair(self, key_id: str, key_pair_spec: str, context: RequestContext):
        key = self._get_key(context, key_id)
        self._validate_key_for_encryption_decryption(key)
        crypto_key = KmsCryptoKey(key_pair_spec)
        return {
            "KeyId": key_id,
            "KeyPairSpec": key_pair_spec,
            "PrivateKeyCiphertextBlob": key.encrypt(crypto_key.private_key),
            "PrivateKeyPlaintext": crypto_key.private_key,
            "PublicKey": crypto_key.public_key,
        }

    @handler("GenerateDataKeyPair", expand=False)
    def generate_data_key_pair(
        self, context: RequestContext, request: GenerateDataKeyPairRequest
    ) -> GenerateDataKeyPairResponse:
        result = self._generate_data_key_pair(
            request.get("KeyId"), request.get("KeyPairSpec"), context
        )
        return GenerateDataKeyPairResponse(**result)

    @handler("GenerateDataKeyPairWithoutPlaintext", expand=False)
    def generate_data_key_pair_without_plaintext(
        self,
        context: RequestContext,
        request: GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> GenerateDataKeyPairWithoutPlaintextResponse:
        result = self._generate_data_key_pair(
            request.get("KeyId"), request.get("KeyPairSpec"), context
        )
        result.pop("PrivateKeyPlaintext")
        return GenerateDataKeyPairResponse(**result)

    # We currently act on neither on KeySpec setting (which is different from and holds values different then
    # KeySpec for CreateKey) nor on NumberOfBytes. Instead, we generate a key with a key length that is "standard" in
    # LocalStack.
    #
    # TODO We also do not use the encryption context. Should reuse the way we do it in encrypt / decrypt.
    def _generate_data_key(self, key_id: str, context: RequestContext):
        key = self._get_key(context, key_id)
        # TODO Should also have a validation for the key being a symmetric one.
        self._validate_key_for_encryption_decryption(key)
        crypto_key = KmsCryptoKey("SYMMETRIC_DEFAULT")
        return {
            "KeyId": key_id,
            "Plaintext": crypto_key.key_material,
            "CiphertextBlob": key.encrypt(crypto_key.key_material),
        }

    @handler("GenerateDataKey", expand=False)
    def generate_data_key(
        self, context: RequestContext, request: GenerateDataKeyRequest
    ) -> GenerateDataKeyResponse:
        result = self._generate_data_key(request.get("KeyId"), context)
        return GenerateDataKeyResponse(**result)

    @handler("GenerateDataKeyWithoutPlaintext", expand=False)
    def generate_data_key_without_plaintext(
        self, context: RequestContext, request: GenerateDataKeyWithoutPlaintextRequest
    ) -> GenerateDataKeyWithoutPlaintextResponse:
        result = self._generate_data_key(request.get("KeyId"), context)
        result.pop("Plaintext")
        return GenerateDataKeyWithoutPlaintextResponse(**result)

    @handler("Sign", expand=False)
    def sign(self, context: RequestContext, request: SignRequest) -> SignResponse:
        key = self._get_key(context, request.get("KeyId"))
        self._validate_key_for_sign_verify(key)

        # TODO Add constraints on KeySpec / SigningAlgorithm pairs:
        #  https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html#key-spec-ecc

        signing_algorithm = request.get("SigningAlgorithm")
        signature = key.sign(request.get("Message"), signing_algorithm)

        result = {
            "KeyId": key.metadata["KeyId"],
            "Signature": signature,
            "SigningAlgorithm": signing_algorithm,
        }
        return SignResponse(**result)

    @handler("Verify", expand=False)
    def verify(self, context: RequestContext, request: VerifyRequest) -> VerifyResponse:
        key = self._get_key(context, request.get("KeyId"))
        self._validate_key_for_sign_verify(key)

        signing_algorithm = request.get("SigningAlgorithm")
        is_signature_valid = key.verify(
            request.get("Message"), signing_algorithm, request.get("Signature")
        )

        result = {
            "KeyId": key.metadata["KeyId"],
            "SignatureValid": is_signature_valid,
            "SigningAlgorithm": signing_algorithm,
        }
        return VerifyResponse(**result)

    def encrypt(
        self,
        context: RequestContext,
        key_id: KeyIdType,
        plaintext: PlaintextType,
        encryption_context: EncryptionContextType = None,
        grant_tokens: GrantTokenList = None,
        encryption_algorithm: EncryptionAlgorithmSpec = None,
    ) -> EncryptResponse:
        key = self._get_key(context, key_id)
        self._validate_key_for_encryption_decryption(key)
        ciphertext_blob = key.encrypt(plaintext)
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        return EncryptResponse(
            CiphertextBlob=ciphertext_blob, KeyId=key_id, EncryptionAlgorithm=encryption_algorithm
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
        key_id = key_id or ciphertext.key_id
        key = self._get_key(context, key_id)
        key_id = key.metadata["KeyId"]
        if key_id != ciphertext.key_id:
            # Haven't checked if this is the exception being raised by AWS in such cases.
            ValidationError(
                f"The supplied KeyId {key_id} doesn't match the KeyId {ciphertext.key_id} present in "
                f"ciphertext. Keep in mind that LocalStack currently doesn't perform asymmetric encryption"
            )
        self._validate_key_for_encryption_decryption(key)

        plaintext = key.decrypt(ciphertext)
        # For compatibility, we return EncryptionAlgorithm values expected from AWS. But LocalStack currently always
        # encrypts with symmetric encryption no matter the key settings.
        #
        # We return a key ARN instead of KeyId despite the name of the parameter, as this is what AWS does and states
        # in its docs.
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
        store = self._get_store(context)
        # KeyId can potentially hold one of multiple different types of key identifiers. get_key finds a key no
        # matter which type of id is used.
        key_to_import_material_to = store.get_key(
            key_id, enabled_key_allowed=True, disabled_key_allowed=True
        )
        if key_to_import_material_to.metadata.get("Origin") != "EXTERNAL":
            raise UnsupportedOperationException(
                "Key material can only be imported into keys with Origin of EXTERNAL"
            )
        self._validate_key_for_encryption_decryption(key_to_import_material_to)
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
        store = self._get_store(context)
        import_token = to_str(import_token)
        import_state = store.imports.get(import_token)
        if not import_state:
            raise NotFoundException(f"Unable to find key import token '{import_token}'")
        key_to_import_material_to = store.get_key(
            key_id, enabled_key_allowed=True, disabled_key_allowed=True
        )
        self._validate_key_for_encryption_decryption(key_to_import_material_to)

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

        key_material = import_state.key.crypto_key.key.decrypt(
            encrypted_key_material, decrypt_padding
        )
        key_to_import_material_to.crypto_key.key_material = key_material
        return ImportKeyMaterialResponse()

    @handler("CreateAlias", expand=False)
    def create_alias(self, context: RequestContext, request: CreateAliasRequest) -> None:
        store = self._get_store(context)
        alias_name = request["AliasName"]
        if alias_name in store.aliases:
            alias_arn = store.aliases.get(alias_name).metadata["AliasArn"]
            # AWS itself uses AliasArn instead of AliasName in this exception.
            raise AlreadyExistsException(f"An alias with the name {alias_arn} already exists")
        # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
        # matter which type of id is used.
        key = self._get_key(
            context, request.get("TargetKeyId"), enabled_key_allowed=True, disabled_key_allowed=True
        )
        request["TargetKeyId"] = key.metadata.get("KeyId")
        alias = KmsAlias(request)
        store.aliases[alias_name] = alias

    @handler("DeleteAlias", expand=False)
    def delete_alias(self, context: RequestContext, request: DeleteAliasRequest) -> None:
        # We do not check the state of the key, as, according to AWS docs, all key states, that are possible in
        # LocalStack, are supported by this operation.
        store = self._get_store(context)
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
        store = self._get_store(context)
        alias = store.get_alias(alias_name, context.account_id, context.region)
        key_id = request["TargetKeyId"]
        # Don't care about the key itself, just want to validate its state.
        store.get_key(key_id, enabled_key_allowed=True, disabled_key_allowed=True)
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
        store = self._get_store(context)
        if key_id:
            # KeyId can potentially hold one of multiple different types of key identifiers. Here we find a key no
            # matter which type of id is used.
            key = store.get_key(key_id, any_key_state_allowed=True)
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
        key = self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
        return GetKeyRotationStatusResponse(KeyRotationEnabled=key.is_key_rotation_enabled)

    @handler("DisableKeyRotation", expand=False)
    def disable_key_rotation(
        self, context: RequestContext, request: DisableKeyRotationRequest
    ) -> None:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the KMS key has imported key material or is in a custom key store: UnsupportedOperationException."
        # We do not model that here, though.
        key = self._get_key(context, request.get("KeyId"))
        key.is_key_rotation_enabled = False

    @handler("EnableKeyRotation", expand=False)
    def enable_key_rotation(
        self, context: RequestContext, request: DisableKeyRotationRequest
    ) -> None:
        # https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
        # "If the KMS key has imported key material or is in a custom key store: UnsupportedOperationException."
        # We do not model that here, though.
        key = self._get_key(context, request.get("KeyId"))
        key.is_key_rotation_enabled = True

    @handler("ListKeyPolicies", expand=False)
    def list_key_policies(
        self, context: RequestContext, request: ListKeyPoliciesRequest
    ) -> ListKeyPoliciesResponse:
        # We just care if the key exists. The response, by AWS specifications, is the same for all keys, as the only
        # supported policy is "default":
        # https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyPolicies.html#API_ListKeyPolicies_ResponseElements
        self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
        return ListKeyPoliciesResponse(PolicyNames=["default"], Truncated=False)

    @handler("PutKeyPolicy", expand=False)
    def put_key_policy(self, context: RequestContext, request: PutKeyPolicyRequest) -> None:
        key = self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
        if request.get("PolicyName") != "default":
            raise UnsupportedOperationException("Only default policy is supported")
        key.policy = request.get("Policy")

    @handler("GetKeyPolicy", expand=False)
    def get_key_policy(
        self, context: RequestContext, request: GetKeyPolicyRequest
    ) -> GetKeyPolicyResponse:
        key = self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
        if request.get("PolicyName") != "default":
            raise NotFoundException("No such policy exists")
        return GetKeyPolicyResponse(Policy=key.policy)

    @handler("ListResourceTags", expand=False)
    def list_resource_tags(
        self, context: RequestContext, request: ListResourceTagsRequest
    ) -> ListResourceTagsResponse:
        key = self._get_key(context, request.get("KeyId"), any_key_state_allowed=True)
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
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
        )
        key.add_tags(request.get("Tags"))

    @handler("UntagResource", expand=False)
    def untag_resource(self, context: RequestContext, request: UntagResourceRequest) -> None:
        key = self._get_key(
            context, request.get("KeyId"), enabled_key_allowed=True, disabled_key_allowed=True
        )
        if not request.get("TagKeys"):
            return
        for tag_key in request.get("TagKeys"):
            # AWS doesn't seem to mind removal of a non-existent tag, so we do not raise any exception.
            key.tags.pop(tag_key, None)

    def _validate_key_for_encryption_decryption(self, key: KmsKey):
        if key.metadata["KeyUsage"] != "ENCRYPT_DECRYPT":
            raise InvalidKeyUsageException(
                "KeyUsage for encryption / decryption should be ENCRYPT_DECRYPT"
            )

    def _validate_key_for_sign_verify(self, key: KmsKey):
        if key.metadata["KeyUsage"] != "SIGN_VERIFY":
            raise InvalidKeyUsageException(
                "KeyUsage for signing / verification key should be SIGN_VERIFY"
            )

    def _validate_grant_request(self, data: Dict, store: KmsStore):
        if "KeyId" not in data or "GranteePrincipal" not in data or "Operations" not in data:
            raise ValidationError("Grant ID, key ID and grantee principal must be specified")

        for operation in data["Operations"]:
            if operation not in VALID_OPERATIONS:
                raise ValidationError(
                    f"Value {['Operations']} at 'operations' failed to satisfy constraint: Member must satisfy"
                    f" constraint: [Member must satisfy enum value set: {VALID_OPERATIONS}]"
                )


# ---------------
# UTIL FUNCTIONS
# ---------------

# Different AWS services have some internal integrations with KMS. Some create keys, that are used to encrypt/decrypt
# customer's data. Such keys can't be created from outside for security reasons. So AWS services use some internal
# APIs to do that. Functions here are supposed to be used by other LocalStack services to have similar integrations
# with KMS in LocalStack. As such, they are supposed to be proper APIs (as in error and security handling),
# just with more features.


def set_key_managed(key_id: str, account_id: str, region: str) -> None:
    store = kms_stores[account_id][region]
    key = store.get_key(key_id)
    key.metadata["KeyManager"] = "AWS"
