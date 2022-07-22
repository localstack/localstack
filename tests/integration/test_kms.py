from datetime import datetime
from random import getrandbits

import botocore.exceptions
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key

from localstack.utils.crypto import encrypt
from localstack.utils.strings import short_uid


class TestKMS:
    @pytest.fixture(scope="class")
    def user_arn(self, sts_client):
        return sts_client.get_caller_identity()["Arn"]

    @pytest.mark.aws_validated
    def test_create_key(self, kms_client, sts_client):
        account_id = sts_client.get_caller_identity()["Account"]
        region = sts_client.meta.region_name

        response = kms_client.list_keys()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        keys_before = response["Keys"]

        response = kms_client.create_key(Description="test key 123", KeyUsage="ENCRYPT_DECRYPT")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        key_id = response["KeyMetadata"]["KeyId"]

        response = kms_client.list_keys()
        assert len(response["Keys"]) == len(keys_before) + 1

        response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert response["KeyId"] == key_id
        assert f":{region}:" in response["Arn"]
        assert f":{account_id}:" in response["Arn"]

    @pytest.mark.aws_validated
    def test_create_grant_with_invalid_key(self, kms_client, user_arn):

        with pytest.raises(botocore.exceptions.ClientError):
            kms_client.create_grant(
                KeyId="invalid",
                GranteePrincipal=user_arn,
                Operations=["Decrypt", "Encrypt"],
            )

    @pytest.mark.aws_validated
    def test_list_grants_with_invalid_key(self, kms_client):
        with pytest.raises(botocore.exceptions.ClientError):
            kms_client.list_grants(
                KeyId="invalid",
            )

    @pytest.mark.aws_validated
    def test_create_grant_with_valid_key(self, kms_client, kms_key, user_arn):
        key_id = kms_key["KeyId"]

        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        grant = kms_client.create_grant(
            KeyId=key_id,
            GranteePrincipal=user_arn,
            Operations=["Decrypt", "Encrypt"],
        )
        assert "GrantId" in grant
        assert "GrantToken" in grant

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) + 1

    @pytest.mark.aws_validated
    def test_revoke_grant(self, kms_client, kms_grant_and_key):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyId"]
        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        kms_client.revoke_grant(KeyId=key_id, GrantId=grant["GrantId"])

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    @pytest.mark.aws_validated
    def test_retire_grant(self, kms_client, kms_grant_and_key):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyId"]
        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        kms_client.retire_grant(GrantToken=grant["GrantToken"])

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    def test_asymmetric_keys(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]

        # generate key pair without plaintext
        result = kms_client.generate_data_key_pair_without_plaintext(
            KeyId=key_id, KeyPairSpec="RSA_2048"
        )
        assert result.get("PrivateKeyCiphertextBlob")
        assert not result.get("PrivateKeyPlaintext")
        assert result.get("PublicKey")

        # generate key pair
        result = kms_client.generate_data_key_pair(KeyId=key_id, KeyPairSpec="RSA_2048")
        assert result.get("PrivateKeyCiphertextBlob")
        assert result.get("PrivateKeyPlaintext")
        assert result.get("PublicKey")

        # get public key
        result1 = kms_client.get_public_key(KeyId=key_id)
        assert result.get("KeyId") == result1.get("KeyId")
        assert result.get("KeyPairSpec") == result1.get("KeySpec")
        assert result.get("PublicKey") == result1.get("PublicKey")

        # assert correct value of encrypted key
        decrypted = kms_client.decrypt(
            CiphertextBlob=result["PrivateKeyCiphertextBlob"], KeyId=key_id
        )
        assert decrypted["Plaintext"] == result["PrivateKeyPlaintext"]

    @pytest.mark.parametrize("key_type", ["rsa", "ecc"])
    def test_sign(self, kms_client, key_type, kms_create_key):
        key_spec = "RSA_2048" if key_type == "rsa" else "ECC_NIST_P256"
        result = kms_create_key(KeyUsage="SIGN_VERIFY", KeySpec=key_spec)
        key_id = result["KeyId"]

        message = b"test message 123 !%$@"
        algo = "RSASSA_PSS_SHA_256" if key_type == "rsa" else "ECDSA_SHA_384"
        result = kms_client.sign(
            KeyId=key_id, Message=message, MessageType="RAW", SigningAlgorithm=algo
        )

        def _verify(signature):
            kwargs = {}
            if key_type == "rsa":
                kwargs["padding"] = padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                )
                kwargs["algorithm"] = hashes.SHA256()
            else:
                kwargs["signature_algorithm"] = ec.ECDSA(algorithm=hashes.SHA384())
            public_key.verify(signature=signature, data=message, **kwargs)

        public_key_data = kms_client.get_public_key(KeyId=key_id)["PublicKey"]
        public_key = serialization.load_der_public_key(public_key_data)
        _verify(result["Signature"])
        with pytest.raises(InvalidSignature):
            _verify(result["Signature"] + b"foobar")

    @pytest.mark.aws_validated
    def test_get_and_list_sign_key(self, kms_client, kms_create_key):
        response = kms_create_key(KeyUsage="SIGN_VERIFY", CustomerMasterKeySpec="ECC_NIST_P256")

        key_id = response["KeyId"]
        describe_response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert describe_response["KeyId"] == key_id

        list_response = kms_client.list_keys()
        found = False
        for keyData in list_response["Keys"]:
            if keyData["KeyId"] == key_id:
                found = True
                break

        assert found is True

    def test_import_key(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]

        # get key import params
        params = kms_client.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_PKCS1_V1_5", WrappingKeySpec="RSA_2048"
        )
        assert params["KeyId"] == key_id
        assert params["ImportToken"]
        assert params["PublicKey"]
        assert isinstance(params["ParametersValidTo"], datetime)

        # create 256 bit symmetric key (import_key_material(..) works with symmetric keys, as per the docs)
        symmetric_key = bytes(getrandbits(8) for _ in range(32))
        assert len(symmetric_key) == 32

        # import symmetric key (key material) into KMS
        public_key = load_der_public_key(params["PublicKey"])
        encrypted_key = public_key.encrypt(symmetric_key, PKCS1v15())
        kms_client.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=encrypted_key,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )

        # use key to encrypt/decrypt data
        plaintext = b"test content 123 !#"
        encrypt_result = kms_client.encrypt(Plaintext=plaintext, KeyId=key_id)
        encrypted = encrypt(symmetric_key, plaintext)
        assert encrypt_result["CiphertextBlob"] == encrypted
        api_decrypted = kms_client.decrypt(
            CiphertextBlob=encrypt_result["CiphertextBlob"], KeyId=key_id
        )
        assert api_decrypted["Plaintext"] == plaintext

    @pytest.mark.aws_validated
    def test_list_aliases_of_key(self, kms_client, kms_create_key):
        aliased_key = kms_create_key()
        comparison_key = kms_create_key()

        alias_name = f"alias/{short_uid()}"

        kms_client.create_alias(AliasName=alias_name, TargetKeyId=aliased_key["KeyId"])

        response = kms_client.list_aliases(KeyId=aliased_key["KeyId"])
        assert len(response["Aliases"]) == 1

        response = kms_client.list_aliases(KeyId=comparison_key["KeyId"])
        assert len(response["Aliases"]) == 0

    # Key ARNs, key IDs, aliases of keys and ARNs of those aliases are supposed to work.
    def test_all_types_of_key_id_can_be_used_for_encryption(
        self, kms_client, kms_create_key, kms_create_alias
    ):
        def get_alias_arn_by_alias_name(kms_client, alias_name):
            for response in kms_client.get_paginator("list_aliases").paginate(KeyId=key_id):
                for alias_list_entry in response["Aliases"]:
                    if alias_list_entry["AliasName"] == alias_name:
                        return alias_list_entry["AliasArn"]

        key_metadata = kms_create_key()
        key_arn = key_metadata["Arn"]
        key_id = key_metadata["KeyId"]
        alias_name = kms_create_alias(TargetKeyId=key_id)
        alias_arn = get_alias_arn_by_alias_name(kms_client, alias_name)
        assert alias_arn
        kms_client.encrypt(KeyId=key_arn, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=key_id, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=alias_arn, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=alias_name, Plaintext="encrypt-me")
