import base64
import hashlib
import json
from datetime import datetime
from random import getrandbits

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key

from localstack.aws.accounts import get_aws_account_id
from localstack.constants import (
    SECONDARY_TEST_AWS_ACCESS_KEY_ID,
    SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
    TEST_AWS_REGION_NAME,
)
from localstack.services.kms.utils import get_hash_algorithm
from localstack.utils.strings import short_uid, to_str


@pytest.fixture(autouse=True)
def kms_api_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.kms_api())


@pytest.fixture(scope="class")
def kms_client_for_region(aws_client_factory):
    def _kms_client(
        region_name: str = None,
    ):
        return aws_client_factory(region_name=region_name).kms

    return _kms_client


def _get_all_key_ids(kms_client):
    ids = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        response = kms_client.list_keys(**kwargs)
        for key in response["Keys"]:
            ids.add(key["KeyId"])
        if "nextToken" not in response:
            break
        next_token = response["nextToken"]
    return ids


def _get_alias(kms_client, alias_name, key_id=None):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        if key_id:
            kwargs["KeyId"] = key_id
        response = kms_client.list_aliases(**kwargs)
        for alias in response["Aliases"]:
            if alias["AliasName"] == alias_name:
                return alias
        if "nextToken" not in response:
            break
        next_token = response["nextToken"]
    return None


class TestKMS:
    @pytest.fixture(scope="class")
    def user_arn(self, aws_client):
        return aws_client.sts.get_caller_identity()["Arn"]

    @pytest.mark.aws_validated
    def test_create_alias(self, kms_create_alias, kms_create_key, snapshot):

        alias_name = f"{short_uid()}"
        alias_key_id = kms_create_key()["KeyId"]
        with pytest.raises(Exception) as e:
            kms_create_alias(AliasName=alias_name, TargetKeyId=alias_key_id)

        snapshot.match("create_alias", e.value.response)

    @pytest.mark.aws_validated
    def test_create_key(self, kms_client_for_region, kms_create_key, snapshot, aws_client):
        region = "us-east-1"
        kms_client = kms_client_for_region(region)
        account_id = aws_client.sts.get_caller_identity()["Account"]

        key_ids_before = _get_all_key_ids(kms_client)

        key_id = kms_create_key(
            region=region, Description="test key 123", KeyUsage="ENCRYPT_DECRYPT"
        )["KeyId"]
        assert key_id not in key_ids_before

        key_ids_after = _get_all_key_ids(kms_client)
        assert key_id in key_ids_after

        response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        snapshot.match("describe-key", response)

        assert response["KeyId"] == key_id
        assert f":{region}:" in response["Arn"]
        assert f":{account_id}:" in response["Arn"]

    @pytest.mark.aws_validated
    def test_get_key_in_different_region(self, kms_client_for_region, kms_create_key, snapshot):
        client_region = "us-east-1"
        key_region = "us-west-2"
        us_east_1_kms_client = kms_client_for_region(client_region)
        us_west_2_kms_client = kms_client_for_region(key_region)

        response = kms_create_key(region=key_region, Description="test key 123")
        key_id = response["KeyId"]
        key_arn = response["Arn"]

        with pytest.raises(ClientError) as e:
            us_east_1_kms_client.describe_key(KeyId=key_id)

        snapshot.match("describe-key-diff-region-with-id", e.value.response)

        with pytest.raises(ClientError) as e:
            us_east_1_kms_client.describe_key(KeyId=key_arn)

        snapshot.match("describe-key-diff-region-with-arn", e.value.response)

        response = us_west_2_kms_client.describe_key(KeyId=key_id)
        snapshot.match("describe-key-same-specific-region-with-id", response)

        response = us_west_2_kms_client.describe_key(KeyId=key_arn)
        snapshot.match("describe-key-same-specific-region-with-arn", response)

    @pytest.mark.aws_validated
    def test_get_key_does_not_exist(self, kms_create_key, snapshot, aws_client):
        # we create a real key to base our fake key ARN on, so we have real account ID and same region
        response = kms_create_key(Description="test key 123")
        key_id = response["KeyId"]
        key_arn = response["Arn"]

        # valid UUID
        fake_key_uuid = "134f2428-cec1-4b25-a1ae-9048164dba47"
        fake_key_arn = key_arn.replace(key_id, fake_key_uuid)

        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId=fake_key_uuid)

        snapshot.match("describe-nonexistent-key-with-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId=fake_key_arn)

        snapshot.match("describe-nonexistent-with-arn", e.value.response)

        # valid multi region keyId
        fake_mr_key_uuid = "mrk-d3b95762d3b95762d3b95762d3b95762"

        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId=fake_mr_key_uuid)

        snapshot.match("describe-key-with-valid-id-mrk", e.value.response)

    @pytest.mark.aws_validated
    def test_get_key_invalid_uuid(self, snapshot, aws_client):
        # valid regular KeyId format
        # "134f2428-cec1-4b25-a1ae-9048164dba47"
        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId="fake-key-id")
        snapshot.match("describe-key-with-invalid-uuid", e.value.response)

        # this UUID is valid for python
        # "134f2428cec14b25a1ae9048164dba47"
        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId="134f2428cec14b25a1ae9048164dba47")
        snapshot.match("describe-key-with-invalid-uuid-2", e.value.response)

        # valid MultiRegionKey KeyId format
        # "mrk-e4b2ea8ffcd4461e9821c9b9521a8896"
        with pytest.raises(ClientError) as e:
            aws_client.kms.describe_key(KeyId="mrk-fake-key-id")
        snapshot.match("describe-key-with-invalid-uuid-mrk", e.value.response)

    @pytest.mark.aws_validated
    def test_list_keys(self, kms_create_key, aws_client):
        created_key = kms_create_key()
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            response = aws_client.kms.list_keys(**kwargs)
            for key in response["Keys"]:
                assert key["KeyId"]
                assert key["KeyArn"]
                if key["KeyId"] == created_key["KeyId"]:
                    assert key["KeyArn"] == created_key["Arn"]
            if "nextToken" not in response:
                break
            next_token = response["nextToken"]

    @pytest.mark.aws_validated
    def test_schedule_and_cancel_key_deletion(self, kms_create_key, aws_client):
        key_id = kms_create_key()["KeyId"]
        aws_client.kms.schedule_key_deletion(KeyId=key_id)
        result = aws_client.kms.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "PendingDeletion"
        assert result["KeyMetadata"]["DeletionDate"]

        aws_client.kms.cancel_key_deletion(KeyId=key_id)
        result = aws_client.kms.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "Disabled"
        assert not result["KeyMetadata"].get("DeletionDate")

    @pytest.mark.aws_validated
    def test_disable_and_enable_key(self, kms_create_key, aws_client):
        key_id = kms_create_key()["KeyId"]
        result = aws_client.kms.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is True
        assert result["KeyMetadata"]["KeyState"] == "Enabled"

        aws_client.kms.disable_key(KeyId=key_id)
        result = aws_client.kms.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "Disabled"

        aws_client.kms.enable_key(KeyId=key_id)
        result = aws_client.kms.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is True
        assert result["KeyMetadata"]["KeyState"] == "Enabled"

    # Not sure how useful this test is, as it just fails during key validation, before grant-specific logic kicks in.
    @pytest.mark.aws_validated
    def test_create_grant_with_invalid_key(self, user_arn, aws_client):

        with pytest.raises(ClientError) as e:
            aws_client.kms.create_grant(
                KeyId="invalid",
                GranteePrincipal=user_arn,
                Operations=["Decrypt", "Encrypt"],
            )
        e.match("NotFoundException")

    # Not sure how useful this test is, as it just fails during key validation, before grant-specific logic kicks in.
    @pytest.mark.aws_validated
    def test_list_grants_with_invalid_key(self, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.kms.list_grants(
                KeyId="invalid",
            )
        e.match("NotFoundException")

    @pytest.mark.aws_validated
    def test_create_grant_with_valid_key(self, kms_key, user_arn, aws_client):
        key_id = kms_key["KeyId"]

        grants_before = aws_client.kms.list_grants(KeyId=key_id)["Grants"]

        grant = aws_client.kms.create_grant(
            KeyId=key_id,
            GranteePrincipal=user_arn,
            Operations=["Decrypt", "Encrypt"],
        )
        assert "GrantId" in grant
        assert "GrantToken" in grant

        grants_after = aws_client.kms.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) + 1

    @pytest.mark.aws_validated
    def test_create_grant_with_same_name_two_keys(self, kms_create_key, user_arn, aws_client):
        first_key_id = kms_create_key()["KeyId"]
        second_key_id = kms_create_key()["KeyId"]

        grant_name = "TestGrantName"

        first_grant = aws_client.kms.create_grant(
            KeyId=first_key_id,
            GranteePrincipal=user_arn,
            Name=grant_name,
            Operations=["Decrypt", "DescribeKey"],
        )
        assert "GrantId" in first_grant
        assert "GrantToken" in first_grant

        second_grant = aws_client.kms.create_grant(
            KeyId=second_key_id,
            GranteePrincipal=user_arn,
            Name=grant_name,
            Operations=["Decrypt", "DescribeKey"],
        )
        assert "GrantId" in second_grant
        assert "GrantToken" in second_grant

        first_grants_after = aws_client.kms.list_grants(KeyId=first_key_id)["Grants"]
        assert len(first_grants_after) == 1

        second_grants_after = aws_client.kms.list_grants(KeyId=second_key_id)["Grants"]
        assert len(second_grants_after) == 1

    @pytest.mark.aws_validated
    def test_revoke_grant(self, kms_grant_and_key, aws_client):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyId"]
        grants_before = aws_client.kms.list_grants(KeyId=key_id)["Grants"]

        aws_client.kms.revoke_grant(KeyId=key_id, GrantId=grant["GrantId"])

        grants_after = aws_client.kms.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    @pytest.mark.aws_validated
    def test_retire_grant_with_grant_token(self, kms_grant_and_key, aws_client):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyId"]
        grants_before = aws_client.kms.list_grants(KeyId=key_id)["Grants"]

        aws_client.kms.retire_grant(GrantToken=grant["GrantToken"])

        grants_after = aws_client.kms.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    @pytest.mark.aws_validated
    def test_retire_grant_with_grant_id_and_key_id(self, kms_grant_and_key, aws_client):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyId"]
        grants_before = aws_client.kms.list_grants(KeyId=key_id)["Grants"]

        aws_client.kms.retire_grant(GrantId=grant["GrantId"], KeyId=key_id)

        grants_after = aws_client.kms.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    # Fails against AWS, as the retiring_principal_arn_prefix is invalid there.
    @pytest.mark.only_localstack
    def test_list_retirable_grants(self, kms_create_key, kms_create_grant, aws_client):
        retiring_principal_arn_prefix = (
            "arn:aws:kms:eu-central-1:123456789876:key/198a5a78-52c3-489f-ac70-"
        )
        right_retiring_principal = retiring_principal_arn_prefix + "000000000001"
        wrong_retiring_principal = retiring_principal_arn_prefix + "000000000002"
        key_id = kms_create_key()["KeyId"]
        right_grant_id = kms_create_grant(KeyId=key_id, RetiringPrincipal=right_retiring_principal)[
            0
        ]
        wrong_grant_id_one = kms_create_grant(
            KeyId=key_id, RetiringPrincipal=wrong_retiring_principal
        )[0]
        wrong_grant_id_two = kms_create_grant(KeyId=key_id)[0]
        wrong_grant_ids = [wrong_grant_id_one, wrong_grant_id_two]

        next_token = None
        right_grant_found = False
        wrong_grant_found = False
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            response = aws_client.kms.list_retirable_grants(
                RetiringPrincipal=right_retiring_principal, **kwargs
            )
            for grant in response["Grants"]:
                if grant["GrantId"] == right_grant_id:
                    right_grant_found = True
                if grant["GrantId"] in wrong_grant_ids:
                    wrong_grant_found = True
            if "nextToken" not in response:
                break
            next_token = response["nextToken"]

        assert right_grant_found
        assert not wrong_grant_found

    @pytest.mark.aws_validated
    def test_generate_data_key_pair_without_plaintext(self, kms_key, aws_client):
        key_id = kms_key["KeyId"]
        result = aws_client.kms.generate_data_key_pair_without_plaintext(
            KeyId=key_id, KeyPairSpec="RSA_2048"
        )
        assert result.get("PrivateKeyCiphertextBlob")
        assert "PrivateKeyPlaintext" not in result
        assert result.get("PublicKey")

    @pytest.mark.aws_validated
    def test_generate_data_key_pair(self, kms_key, aws_client):
        key_id = kms_key["KeyId"]
        result = aws_client.kms.generate_data_key_pair(KeyId=key_id, KeyPairSpec="RSA_2048")
        assert result.get("PrivateKeyCiphertextBlob")
        assert result.get("PrivateKeyPlaintext")
        assert result.get("PublicKey")

        # assert correct value of encrypted key
        decrypted = aws_client.kms.decrypt(
            CiphertextBlob=result["PrivateKeyCiphertextBlob"], KeyId=key_id
        )
        assert decrypted["Plaintext"] == result["PrivateKeyPlaintext"]

    @pytest.mark.parametrize("number_of_bytes", [12, 44, 91, 1, 1024])
    @pytest.mark.aws_validated
    def test_generate_random(self, snapshot, number_of_bytes, aws_client):
        result = aws_client.kms.generate_random(NumberOfBytes=number_of_bytes)

        plain_text = result.get("Plaintext")

        assert plain_text
        assert isinstance(plain_text, bytes)
        assert len(plain_text) == number_of_bytes
        snapshot.match("result_length", len(plain_text))

    @pytest.mark.parametrize("number_of_bytes", [None, 0, 1025])
    @pytest.mark.aws_validated
    def test_generate_random_invalid_number_of_bytes(
        self, create_boto_client, snapshot, number_of_bytes
    ):
        kms_client = create_boto_client("kms", additional_config=Config(parameter_validation=False))

        with pytest.raises(ClientError) as e:
            kms_client.generate_random(NumberOfBytes=number_of_bytes)

        snapshot.match("generate-random-exc", e.value.response)

    @pytest.mark.aws_validated
    def test_generate_data_key(self, kms_key, aws_client):
        key_id = kms_key["KeyId"]
        # LocalStack currently doesn't act on KeySpec or on NumberOfBytes params, but one of them has to be set.
        result = aws_client.kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        assert result.get("CiphertextBlob")
        assert result.get("Plaintext")
        assert result.get("KeyId")

        # assert correct value of encrypted key
        decrypted = aws_client.kms.decrypt(CiphertextBlob=result["CiphertextBlob"], KeyId=key_id)
        assert decrypted["Plaintext"] == result["Plaintext"]

    @pytest.mark.aws_validated
    def test_generate_data_key_without_plaintext(self, kms_key, aws_client):
        key_id = kms_key["KeyId"]
        # LocalStack currently doesn't act on KeySpec or on NumberOfBytes params, but one of them has to be set.
        result = aws_client.kms.generate_data_key_without_plaintext(KeyId=key_id, KeySpec="AES_256")
        assert result.get("CiphertextBlob")
        assert "Plaintext" not in result
        assert result.get("KeyId")

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Error.Message",
            "$..message",
        ]
    )
    @pytest.mark.parametrize(
        "key_spec,sign_algo",
        [
            ("RSA_2048", "RSASSA_PSS_SHA_256"),
            ("RSA_2048", "RSASSA_PSS_SHA_384"),
            ("RSA_2048", "RSASSA_PSS_SHA_512"),
            ("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_256"),
            ("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_512"),
            ("ECC_NIST_P256", "ECDSA_SHA_256"),
            ("ECC_NIST_P384", "ECDSA_SHA_384"),
            ("ECC_SECG_P256K1", "ECDSA_SHA_256"),
        ],
    )
    def test_sign_verify(self, kms_create_key, snapshot, key_spec, sign_algo, aws_client):
        hash_algo = get_hash_algorithm(sign_algo)
        hasher = getattr(hashlib, hash_algo.replace("_", "").lower())

        plaintext = b"test message !%$@ 1234567890"
        digest = hasher(plaintext).digest()

        key_id = kms_create_key(KeyUsage="SIGN_VERIFY", KeySpec=key_spec)["KeyId"]

        kwargs = {"KeyId": key_id, "SigningAlgorithm": sign_algo}

        bad_signature = aws_client.kms.sign(MessageType="RAW", Message="bad", **kwargs)["Signature"]
        bad_message = b"bad message 321"

        # Ensure raw messages can be signed and verified
        signature = aws_client.kms.sign(MessageType="RAW", Message=plaintext, **kwargs)
        snapshot.match("signature", signature)
        verification = aws_client.kms.verify(
            MessageType="RAW", Signature=signature["Signature"], Message=plaintext, **kwargs
        )
        snapshot.match("verification", verification)
        assert verification["SignatureValid"]

        # Ensure pre-hashed messages can be signed and verified
        signature = aws_client.kms.sign(MessageType="DIGEST", Message=digest, **kwargs)
        verification = aws_client.kms.verify(
            MessageType="DIGEST", Signature=signature["Signature"], Message=digest, **kwargs
        )
        assert verification["SignatureValid"]

        # Ensure bad digest raises during signing
        with pytest.raises(ClientError) as exc:
            aws_client.kms.sign(MessageType="DIGEST", Message=plaintext, **kwargs)
        assert exc.match("ValidationException")
        snapshot.match("bad-digest", exc.value.response)

        # Ensure bad signature raises during verify
        with pytest.raises(ClientError) as exc:
            aws_client.kms.verify(
                MessageType="RAW", Signature=bad_signature, Message=plaintext, **kwargs
            )
        assert exc.match("KMSInvalidSignatureException")
        snapshot.match("bad-signature", exc.value.response)

        # Ensure bad message raises during verify
        with pytest.raises(ClientError) as exc:
            aws_client.kms.verify(
                MessageType="RAW", Signature=signature["Signature"], Message=bad_message, **kwargs
            )
        assert exc.match("KMSInvalidSignatureException")

        # Ensure bad digest raises during verify
        with pytest.raises(ClientError) as exc:
            aws_client.kms.verify(
                MessageType="DIGEST",
                Signature=signature["Signature"],
                Message=bad_message,
                **kwargs,
            )
        assert exc.match("ValidationException")

    def test_invalid_key_usage(self, kms_create_key, aws_client):
        key_id = kms_create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="RSA_4096")["KeyId"]
        with pytest.raises(ClientError) as exc:
            aws_client.kms.sign(
                MessageType="RAW",
                Message="hello",
                KeyId=key_id,
                SigningAlgorithm="RSASSA_PSS_SHA_256",
            )
        assert exc.match("InvalidKeyUsageException")

        key_id = kms_create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_4096")["KeyId"]
        with pytest.raises(ClientError) as exc:
            aws_client.kms.encrypt(
                Plaintext="hello",
                KeyId=key_id,
                EncryptionAlgorithm="RSAES_OAEP_SHA_256",
            )
        assert exc.match("InvalidKeyUsageException")

    @pytest.mark.parametrize(
        "key_spec,algo",
        [
            ("SYMMETRIC_DEFAULT", "SYMMETRIC_DEFAULT"),
            ("RSA_2048", "RSAES_OAEP_SHA_256"),
        ],
    )
    def test_encrypt_decrypt(self, kms_create_key, key_spec, algo, aws_client):
        key_id = kms_create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec=key_spec)["KeyId"]
        message = b"test message 123 !%$@ 1234567890"
        ciphertext = aws_client.kms.encrypt(
            KeyId=key_id, Plaintext=base64.b64encode(message), EncryptionAlgorithm=algo
        )["CiphertextBlob"]
        plaintext = aws_client.kms.decrypt(
            KeyId=key_id, CiphertextBlob=ciphertext, EncryptionAlgorithm=algo
        )["Plaintext"]
        assert base64.b64decode(plaintext) == message

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "key_spec,algo",
        [
            ("RSA_2048", "RSAES_OAEP_SHA_1"),
            ("RSA_2048", "RSAES_OAEP_SHA_256"),
            ("RSA_3072", "RSAES_OAEP_SHA_1"),
            ("RSA_3072", "RSAES_OAEP_SHA_256"),
            ("RSA_4096", "RSAES_OAEP_SHA_1"),
            ("RSA_4096", "RSAES_OAEP_SHA_256"),
        ],
    )
    def test_encrypt_validate_plaintext_size_per_key_type(
        self, kms_create_key, key_spec, algo, snapshot, aws_client
    ):
        key_id = kms_create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec=key_spec)["KeyId"]
        message = b"more than 500 bytes and less than 4096 bytes" * 20
        with pytest.raises(ClientError) as e:
            aws_client.kms.encrypt(
                KeyId=key_id, Plaintext=base64.b64encode(message), EncryptionAlgorithm=algo
            )
        snapshot.match("generate-random-exc", e.value.response)

    @pytest.mark.aws_validated
    def test_get_public_key(self, kms_create_key, aws_client):
        key = kms_create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="RSA_2048")
        response = aws_client.kms.get_public_key(KeyId=key["KeyId"])
        assert response.get("KeyId") == key["Arn"]
        assert response.get("KeySpec") == key["KeySpec"]
        assert response.get("KeyUsage") == key["KeyUsage"]
        assert response.get("PublicKey")

    @pytest.mark.aws_validated
    def test_describe_and_list_sign_key(self, kms_create_key, aws_client):
        response = kms_create_key(KeyUsage="SIGN_VERIFY", CustomerMasterKeySpec="ECC_NIST_P256")

        key_id = response["KeyId"]
        describe_response = aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        assert describe_response["KeyId"] == key_id
        assert key_id in _get_all_key_ids(aws_client.kms)

    @pytest.mark.aws_validated
    def test_import_key(self, kms_create_key, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("Description"))
        key = kms_create_key(Origin="EXTERNAL")
        snapshot.match("created-key", key)
        key_id = key["KeyId"]

        # try key before importing
        plaintext = b"test content 123 !#"
        with pytest.raises(ClientError) as e:
            aws_client.kms.encrypt(Plaintext=plaintext, KeyId=key_id)
        snapshot.match("encrypt-before-import-error", e.value.response)

        # get key import params
        params = aws_client.kms.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_PKCS1_V1_5", WrappingKeySpec="RSA_2048"
        )
        assert params["KeyId"] == key["Arn"]
        assert params["ImportToken"]
        assert params["PublicKey"]
        assert isinstance(params["ParametersValidTo"], datetime)

        # create 256 bit symmetric key (import_key_material(..) works with symmetric keys, as per the docs)
        symmetric_key = bytes(getrandbits(8) for _ in range(32))
        assert len(symmetric_key) == 32

        # import symmetric key (key material) into KMS
        public_key = load_der_public_key(params["PublicKey"])
        encrypted_key = public_key.encrypt(symmetric_key, PKCS1v15())
        describe_key_before_import = aws_client.kms.describe_key(KeyId=key_id)
        snapshot.match("describe-key-before-import", describe_key_before_import)

        with pytest.raises(ClientError) as e:
            aws_client.kms.import_key_material(
                KeyId=key_id,
                ImportToken=params["ImportToken"],
                EncryptedKeyMaterial=encrypted_key,
            )
        snapshot.match("import-expiring-key-without-valid-to", e.value.response)
        aws_client.kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=encrypted_key,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
        describe_key_after_import = aws_client.kms.describe_key(KeyId=key_id)
        snapshot.match("describe-key-after-import", describe_key_after_import)

        # use key to encrypt/decrypt data
        encrypt_result = aws_client.kms.encrypt(Plaintext=plaintext, KeyId=key_id)
        api_decrypted = aws_client.kms.decrypt(
            CiphertextBlob=encrypt_result["CiphertextBlob"], KeyId=key_id
        )
        assert api_decrypted["Plaintext"] == plaintext

        aws_client.kms.delete_imported_key_material(KeyId=key_id)
        describe_key_after_deleted_import = aws_client.kms.describe_key(KeyId=key_id)
        snapshot.match("describe-key-after-deleted-import", describe_key_after_deleted_import)

        with pytest.raises(ClientError) as e:
            aws_client.kms.encrypt(Plaintext=plaintext, KeyId=key_id)
        snapshot.match("encrypt-after-delete-error", e.value.response)

    @pytest.mark.aws_validated
    def test_list_aliases_of_key(self, kms_create_key, kms_create_alias, aws_client):
        aliased_key_id = kms_create_key()["KeyId"]
        comparison_key_id = kms_create_key()["KeyId"]

        alias_name = f"alias/{short_uid()}"
        kms_create_alias(AliasName=alias_name, TargetKeyId=aliased_key_id)

        assert _get_alias(aws_client.kms, alias_name, aliased_key_id) is not None
        assert _get_alias(aws_client.kms, alias_name, comparison_key_id) is None

    @pytest.mark.aws_validated
    def test_all_types_of_key_id_can_be_used_for_encryption(
        self, kms_create_key, kms_create_alias, aws_client
    ):
        def get_alias_arn_by_alias_name(kms_client, alias_name):
            for response in kms_client.get_paginator("list_aliases").paginate(KeyId=key_id):
                for alias_list_entry in response["Aliases"]:
                    if alias_list_entry["AliasName"] == alias_name:
                        return alias_list_entry["AliasArn"]
            return None

        key_metadata = kms_create_key()
        key_arn = key_metadata["Arn"]
        key_id = key_metadata["KeyId"]
        alias_name = kms_create_alias(TargetKeyId=key_id)
        alias_arn = get_alias_arn_by_alias_name(aws_client.kms, alias_name)
        assert alias_arn
        aws_client.kms.encrypt(KeyId=key_arn, Plaintext="encrypt-me")
        aws_client.kms.encrypt(KeyId=key_id, Plaintext="encrypt-me")
        aws_client.kms.encrypt(KeyId=alias_arn, Plaintext="encrypt-me")
        aws_client.kms.encrypt(KeyId=alias_name, Plaintext="encrypt-me")

    @pytest.mark.aws_validated
    def test_create_multi_region_key(self, kms_create_key):
        key = kms_create_key(MultiRegion=True)
        assert key["KeyId"].startswith("mrk-")
        assert key["MultiRegion"]

    @pytest.mark.aws_validated
    def test_non_multi_region_keys_should_not_have_multi_region_properties(self, kms_create_key):
        key = kms_create_key(MultiRegion=False)
        assert not key["KeyId"].startswith("mrk-")
        assert not key["MultiRegion"]

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..KeyMetadata.Enabled",
            "$..KeyMetadata.KeyState",
            "$..KeyMetadata.MultiRegionConfiguration",  # not implemented
            "$..ReplicaKeyMetadata.Enabled",
            "$..ReplicaKeyMetadata.KeyState",
            "$..ReplicaKeyMetadata.MultiRegionConfiguration",  # not implemented
            "$..ReplicaPolicy",  # not implemented
        ],
    )
    def test_replicate_key(
        self, kms_client_for_region, kms_create_key, kms_replicate_key, snapshot
    ):
        region_to_replicate_from = "us-east-1"
        region_to_replicate_to = "us-west-1"
        us_east_1_kms_client = kms_client_for_region(region_to_replicate_from)
        us_west_1_kms_client = kms_client_for_region(region_to_replicate_to)

        key_id = kms_create_key(
            region=region_to_replicate_from, MultiRegion=True, Description="test replicated key"
        )["KeyId"]

        with pytest.raises(ClientError) as e:
            us_west_1_kms_client.describe_key(KeyId=key_id)
        snapshot.match("describe-key-from-different-region", e.value.response)

        response = kms_replicate_key(
            region_from=region_to_replicate_from, KeyId=key_id, ReplicaRegion=region_to_replicate_to
        )
        snapshot.match("replicate-key", response)
        # assert response.get("ReplicaKeyMetadata")
        # describe original key with the client from its region
        response = us_east_1_kms_client.describe_key(KeyId=key_id)
        snapshot.match("describe-key-from-region", response)

        # describe replicated key
        response = us_west_1_kms_client.describe_key(KeyId=key_id)
        snapshot.match("describe-replicated-key", response)

    @pytest.mark.aws_validated
    def test_update_key_description(self, kms_create_key, aws_client):
        old_description = "old_description"
        new_description = "new_description"
        key = kms_create_key(Description=old_description)
        key_id = key["KeyId"]
        assert (
            aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
            == old_description
        )
        result = aws_client.kms.update_key_description(KeyId=key_id, Description=new_description)
        assert "ResponseMetadata" in result
        assert (
            aws_client.kms.describe_key(KeyId=key_id)["KeyMetadata"]["Description"]
            == new_description
        )

    @pytest.mark.aws_validated
    def test_key_rotation_status(self, kms_key, aws_client):
        key_id = kms_key["KeyId"]
        # According to AWS docs, supposed to be False by default.
        assert aws_client.kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is False
        aws_client.kms.enable_key_rotation(KeyId=key_id)
        assert aws_client.kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is True
        aws_client.kms.disable_key_rotation(KeyId=key_id)
        assert aws_client.kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is False

    @pytest.mark.aws_validated
    def test_create_list_delete_alias(self, kms_create_alias, aws_client):
        alias_name = f"alias/{short_uid()}"
        assert _get_alias(aws_client.kms, alias_name) is None
        kms_create_alias(AliasName=alias_name)
        assert _get_alias(aws_client.kms, alias_name) is not None
        aws_client.kms.delete_alias(AliasName=alias_name)
        assert _get_alias(aws_client.kms, alias_name) is None

    @pytest.mark.aws_validated
    def test_update_alias(self, kms_create_key, kms_create_alias, aws_client):
        alias_name = f"alias/{short_uid()}"
        old_key_id = kms_create_key()["KeyId"]
        kms_create_alias(AliasName=alias_name, TargetKeyId=old_key_id)
        alias = _get_alias(aws_client.kms, alias_name, old_key_id)
        assert alias is not None
        assert alias["TargetKeyId"] == old_key_id

        new_key_id = kms_create_key()["KeyId"]
        aws_client.kms.update_alias(AliasName=alias_name, TargetKeyId=new_key_id)
        alias = _get_alias(aws_client.kms, alias_name, new_key_id)
        assert alias is not None
        assert alias["TargetKeyId"] == new_key_id

    # Fails in AWS, as the principal is invalid there.
    # Maybe would work if get_aws_account_id() starts returning an actual AWS account ID.
    @pytest.mark.only_localstack
    def test_get_put_list_key_policies(self, kms_create_key, aws_client):
        base_policy = {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "This is the default key policy",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{get_aws_account_id()}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "This is some additional stuff to look special",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{get_aws_account_id()}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ],
        }
        policy_one = base_policy.copy()
        policy_one["Statement"][1]["Action"] = "kms:ListAliases"
        policy_one = json.dumps(policy_one)
        policy_two = base_policy.copy()
        policy_two["Statement"][1]["Action"] = "kms:ListGrants"
        policy_two = json.dumps(policy_two)

        key_id = kms_create_key(Policy=policy_one)["KeyId"]
        # AWS currently supports only the default policy, so just a fixed response.
        response = aws_client.kms.list_key_policies(KeyId=key_id)
        assert response.get("PolicyNames") == ["default"]
        assert response.get("Truncated") is False
        assert (
            aws_client.kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            == policy_one
        )
        aws_client.kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy_two)
        assert (
            aws_client.kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            == policy_two
        )

    @pytest.mark.aws_validated
    def test_tag_untag_list_tags(self, kms_create_key, aws_client):
        def _create_tag(key):
            return {"TagKey": key, "TagValue": short_uid()}

        def _are_tags_there(tags, key_id):
            if not tags:
                return True
            next_token = None
            while True:
                kwargs = {"nextToken": next_token} if next_token else {}
                response = aws_client.kms.list_resource_tags(KeyId=key_id, **kwargs)
                for response_tag in response["Tags"]:
                    for i in range(len(tags)):
                        if response_tag.get("TagKey") == tags[i].get("TagKey") and response_tag.get(
                            "TagValue"
                        ) == tags[i].get("TagValue"):
                            del tags[i]
                            if not tags:
                                return True
                            break
                if "nextToken" not in response:
                    break
                next_token = response["nextToken"]
            return False

        old_tag_one = _create_tag("one")
        new_tag_one = _create_tag("one")
        tag_two = _create_tag("two")
        tag_three = _create_tag("three")

        key_id = kms_create_key(Tags=[old_tag_one, tag_two])["KeyId"]
        assert _are_tags_there([old_tag_one, tag_two], key_id) is True
        # Going to rewrite one of the tags and then add a new one.
        aws_client.kms.tag_resource(KeyId=key_id, Tags=[new_tag_one, tag_three])
        assert _are_tags_there([new_tag_one, tag_two, tag_three], key_id) is True
        assert _are_tags_there([old_tag_one], key_id) is False
        aws_client.kms.untag_resource(KeyId=key_id, TagKeys=[new_tag_one.get("TagKey")])
        assert _are_tags_there([tag_two, tag_three], key_id) is True
        assert _are_tags_there([new_tag_one], key_id) is False

    @pytest.mark.aws_validated
    def test_cant_use_disabled_or_deleted_keys(self, kms_create_key, aws_client):
        key_id = kms_create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")["KeyId"]
        aws_client.kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")

        aws_client.kms.disable_key(KeyId=key_id)
        with pytest.raises(ClientError) as e:
            aws_client.kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        e.match("DisabledException")

        aws_client.kms.schedule_key_deletion(KeyId=key_id)
        with pytest.raises(ClientError) as e:
            aws_client.kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        e.match("KMSInvalidStateException")

    @pytest.mark.aws_validated
    def test_cant_delete_deleted_key(self, kms_create_key, aws_client):
        key_id = kms_create_key()["KeyId"]
        aws_client.kms.schedule_key_deletion(KeyId=key_id)

        with pytest.raises(ClientError) as e:
            aws_client.kms.schedule_key_deletion(KeyId=key_id)
        e.match("KMSInvalidStateException")

    @pytest.mark.aws_validated
    def test_hmac_create_key(self, kms_client_for_region, kms_create_key, snapshot):
        region = "us-east-1"
        kms_client = kms_client_for_region(region)
        key_ids_before = _get_all_key_ids(kms_client)

        response = kms_create_key(
            region=region,
            Description="test key",
            KeySpec="HMAC_256",
            KeyUsage="GENERATE_VERIFY_MAC",
        )
        key_id = response["KeyId"]
        snapshot.match("create-hmac-key", response)

        assert key_id not in key_ids_before
        key_ids_after = _get_all_key_ids(kms_client)
        assert key_id in key_ids_after

        response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        snapshot.match("describe-key", response)

    @pytest.mark.aws_validated
    def test_hmac_create_key_invalid_operations(self, kms_create_key, snapshot):
        with pytest.raises(ClientError) as e:
            kms_create_key(Description="test HMAC key without key usage", KeySpec="HMAC_256")
        snapshot.match("create-hmac-key-without-key-usage", e.value.response)

        with pytest.raises(ClientError) as e:
            kms_create_key(Description="test invalid HMAC spec", KeySpec="HMAC_random")
        snapshot.match("create-hmac-key-invalid-spec", e.value.response)

        with pytest.raises(ClientError) as e:
            kms_create_key(
                region="us-east-1",
                Description="test invalid HMAC spec",
                KeySpec="HMAC_256",
                KeyUsage="RANDOM",
            )
        snapshot.match("create-hmac-key-invalid-key-usage", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "key_spec,mac_algo",
        [
            ("HMAC_224", "HMAC_SHA_224"),
            ("HMAC_256", "HMAC_SHA_256"),
            ("HMAC_384", "HMAC_SHA_384"),
            ("HMAC_512", "HMAC_SHA_512"),
        ],
    )
    def test_generate_and_verify_mac(
        self, kms_create_key, key_spec, mac_algo, snapshot, aws_client
    ):
        key_id = kms_create_key(
            Description="test hmac key",
            KeySpec=key_spec,
            KeyUsage="GENERATE_VERIFY_MAC",
        )["KeyId"]

        generate_mac_response = aws_client.kms.generate_mac(
            KeyId=key_id,
            Message="some important message",
            MacAlgorithm=mac_algo,
        )
        snapshot.match("generate-mac", generate_mac_response)

        verify_mac_response = aws_client.kms.verify_mac(
            KeyId=key_id,
            Message="some important message",
            MacAlgorithm=mac_algo,
            Mac=generate_mac_response["Mac"],
        )
        snapshot.match("verify-mac", verify_mac_response)

        # test generate mac with invalid key-id
        with pytest.raises(ClientError) as e:
            aws_client.kms.generate_mac(
                KeyId="key_id",
                Message="some important message",
                MacAlgorithm=mac_algo,
            )
        snapshot.match("generate-mac-invalid-key-id", e.value.response)

        # test verify mac with invalid key-id
        with pytest.raises(ClientError) as e:
            aws_client.kms.verify_mac(
                KeyId="key_id",
                Message="some important message",
                MacAlgorithm=mac_algo,
                Mac=generate_mac_response["Mac"],
            )
        snapshot.match("verify-mac-invalid-key-id", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "key_spec,mac_algo",
        [
            ("HMAC_224", "HMAC_SHA_256"),
            ("HMAC_256", "INVALID"),
        ],
    )
    def test_invalid_generate_mac(self, kms_create_key, key_spec, mac_algo, snapshot, aws_client):
        key_id = kms_create_key(
            Description="test hmac key",
            KeySpec=key_spec,
            KeyUsage="GENERATE_VERIFY_MAC",
        )["KeyId"]

        with pytest.raises(ClientError) as e:
            aws_client.kms.generate_mac(
                KeyId=key_id,
                Message="some important message",
                MacAlgorithm=mac_algo,
            )
        snapshot.match("generate-mac", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..message"])
    @pytest.mark.parametrize(
        "key_spec,mac_algo,verify_msg",
        [
            ("HMAC_256", "HMAC_SHA_256", "some different important message"),
            ("HMAC_256", "HMAC_SHA_512", "some important message"),
            ("HMAC_256", "INVALID", "some important message"),
        ],
    )
    def test_invalid_verify_mac(
        self, kms_create_key, key_spec, mac_algo, verify_msg, snapshot, aws_client
    ):
        key_id = kms_create_key(
            Description="test hmac key",
            KeySpec=key_spec,
            KeyUsage="GENERATE_VERIFY_MAC",
        )["KeyId"]

        generate_mac_response = aws_client.kms.generate_mac(
            KeyId=key_id,
            Message="some important message",
            MacAlgorithm="HMAC_SHA_256",
        )
        snapshot.match("generate-mac", generate_mac_response)

        with pytest.raises(ClientError) as e:
            aws_client.kms.verify_mac(
                KeyId=key_id,
                Message=verify_msg,
                MacAlgorithm=mac_algo,
                Mac=generate_mac_response["Mac"],
            )
        snapshot.match("verify-mac", e.value.response)

    @pytest.mark.aws_validated
    def test_error_messaging_for_invalid_keys(self, aws_client, kms_create_key, snapshot):
        hmac_key_id = kms_create_key(
            Description="test key hmac",
            KeySpec="HMAC_224",
            KeyUsage="GENERATE_VERIFY_MAC",
        )["KeyId"]

        encrypt_decrypt_key_id = kms_create_key(Description="test key encrypt decrypt")["KeyId"]

        sign_verify_key_id = kms_create_key(
            Description="test key sign verify", KeyUsage="SIGN_VERIFY", KeySpec="RSA_2048"
        )["KeyId"]

        # test generate mac with invalid key id
        with pytest.raises(ClientError) as e:
            aws_client.kms.generate_mac(
                KeyId=encrypt_decrypt_key_id,
                Message="some important message",
                MacAlgorithm="HMAC_SHA_224",
            )
        snapshot.match("generate-mac-invalid-key-id", e.value.response)

        # test create signature for a message with invalid key id
        kwargs = {"KeyId": hmac_key_id, "SigningAlgorithm": "RSASSA_PSS_SHA_256"}
        with pytest.raises(ClientError) as e:
            aws_client.kms.sign(MessageType="RAW", Message="test message 123!@#", **kwargs)
        snapshot.match("sign-invalid-key-id", e.value.response)

        # test verify signature for a message with invalid key id
        with pytest.raises(ClientError) as e:
            aws_client.kms.verify(
                MessageType="RAW",
                Signature=b"random text",
                Message="test message",
                KeyId=encrypt_decrypt_key_id,
                SigningAlgorithm="ECDSA_SHA_256",
            )
        snapshot.match("verify-invalid-key-id", e.value.response)

        # test encrypting a text with invalid key id
        with pytest.raises(ClientError) as e:
            aws_client.kms.encrypt(Plaintext="test message 123!@#", KeyId=sign_verify_key_id)
        snapshot.match("encrypt-invalid-key-id", e.value.response)

        # test decrypting a text with invalid key id
        ciphertext_blob = aws_client.kms.encrypt(
            Plaintext="test message 123!@#", KeyId=encrypt_decrypt_key_id
        )["CiphertextBlob"]
        with pytest.raises(ClientError) as e:
            aws_client.kms.decrypt(CiphertextBlob=ciphertext_blob, KeyId=hmac_key_id)
        snapshot.match("decrypt-invalid-key-id", e.value.response)

    @pytest.mark.aws_validated
    def test_plaintext_size_for_encrypt(self, kms_create_key, snapshot, aws_client):
        key_id = kms_create_key()["KeyId"]
        message = b"test message 123 !%$@ 1234567890"

        with pytest.raises(ClientError) as e:
            aws_client.kms.encrypt(KeyId=key_id, Plaintext=base64.b64encode(message * 100))
        snapshot.match("invalid-plaintext-size-encrypt", e.value.response)

    def test_cross_accounts_access(self, aws_client, aws_client_factory, kms_create_key, user_arn):
        # Create the keys in the primary AWS account. They will only be referred to by their ARNs hereon
        key_arn_1 = kms_create_key()["Arn"]
        key_arn_2 = kms_create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_4096")["Arn"]
        key_arn_3 = kms_create_key(KeyUsage="GENERATE_VERIFY_MAC", KeySpec="HMAC_512")["Arn"]

        # Create client in secondary account and attempt to run operations with the above keys
        client = aws_client_factory.get_client(
            "kms",
            aws_access_key_id=SECONDARY_TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
            region_name=TEST_AWS_REGION_NAME,
        )

        # Cross-account access is supported for following operations in KMS:
        # - CreateGrant
        # - DescribeKey
        # - GetKeyRotationStatus
        # - GetPublicKey
        # - ListGrants
        # - RetireGrant
        # - RevokeGrant

        response = client.create_grant(
            KeyId=key_arn_1,
            GranteePrincipal=user_arn,
            Operations=["Decrypt", "Encrypt"],
        )
        grant_token = response["GrantToken"]

        response = client.create_grant(
            KeyId=key_arn_2,
            GranteePrincipal=user_arn,
            Operations=["Sign", "Verify"],
        )
        grant_id = response["GrantId"]

        assert client.describe_key(KeyId=key_arn_1)["KeyMetadata"]

        assert client.get_key_rotation_status(KeyId=key_arn_1)

        assert client.get_public_key(KeyId=key_arn_1)

        assert client.list_grants(KeyId=key_arn_1)["Grants"]

        assert client.retire_grant(GrantToken=grant_token)

        assert client.revoke_grant(GrantId=grant_id, KeyId=key_arn_2)

        # And additionally, the following cryptographic operations:
        # - Decrypt
        # - Encrypt
        # - GenerateDataKey
        # - GenerateDataKeyPair
        # - GenerateDataKeyPairWithoutPlaintext
        # - GenerateDataKeyWithoutPlaintext
        # - GenerateMac
        # - ReEncrypt (NOT IMPLEMENTED IN LOCALSTACK)
        # - Sign
        # - Verify
        # - VerifyMac

        assert client.generate_data_key(KeyId=key_arn_1)

        assert client.generate_data_key_without_plaintext(KeyId=key_arn_1)

        assert client.generate_data_key_pair(KeyId=key_arn_1, KeyPairSpec="RSA_2048")

        assert client.generate_data_key_pair_without_plaintext(
            KeyId=key_arn_1, KeyPairSpec="RSA_2048"
        )

        plaintext = "hello"
        ciphertext = client.encrypt(KeyId=key_arn_1, Plaintext="hello")["CiphertextBlob"]

        response = client.decrypt(CiphertextBlob=ciphertext, KeyId=key_arn_1)
        assert plaintext == to_str(response["Plaintext"])

        message = "world"
        signature = client.sign(
            KeyId=key_arn_2,
            MessageType="RAW",
            Message=message,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )["Signature"]

        assert client.verify(
            KeyId=key_arn_2,
            Signature=signature,
            Message=message,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )["SignatureValid"]

        mac = client.generate_mac(KeyId=key_arn_3, Message=message, MacAlgorithm="HMAC_SHA_512")[
            "Mac"
        ]

        assert client.verify_mac(
            KeyId=key_arn_3, Message=message, MacAlgorithm="HMAC_SHA_512", Mac=mac
        )["MacValid"]
