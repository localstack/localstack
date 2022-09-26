import json
from datetime import datetime
from random import getrandbits

import botocore.exceptions
import pytest
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key

from localstack.aws.accounts import get_aws_account_id
from localstack.utils.aws.aws_stack import get_region
from localstack.utils.strings import short_uid


def _get_all_key_ids(kms_client):
    ids = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        response = kms_client.list_keys(**kwargs)
        for key in response["Keys"]:
            print(key)
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
    def user_arn(self, sts_client):
        return sts_client.get_caller_identity()["Arn"]

    # Not AWS validated anymore, as get_region() doesn't return the region used in AWS.
    @pytest.mark.only_localstack
    def test_create_key(self, kms_client, sts_client):
        account_id = get_aws_account_id()
        region = get_region()

        key_ids_before = _get_all_key_ids(kms_client)

        response = kms_client.create_key(Description="test key 123", KeyUsage="ENCRYPT_DECRYPT")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        key_id = response["KeyMetadata"]["KeyId"]
        assert key_id not in key_ids_before

        key_ids_after = _get_all_key_ids(kms_client)
        assert key_id in key_ids_after

        response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert response["KeyId"] == key_id
        assert f":{region}:" in response["Arn"]
        assert f":{account_id}:" in response["Arn"]

    @pytest.mark.aws_validated
    def test_list_keys(self, kms_client, kms_create_key):
        created_key = kms_create_key()
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            response = kms_client.list_keys(**kwargs)
            for key in response["Keys"]:
                assert key["KeyId"]
                assert key["KeyArn"]
                if key["KeyId"] == created_key["KeyId"]:
                    assert key["KeyArn"] == created_key["Arn"]
            if "nextToken" not in response:
                break
            next_token = response["nextToken"]

    @pytest.mark.aws_validated
    def test_schedule_and_cancel_key_deletion(self, kms_client, kms_create_key):
        key_id = kms_create_key()["KeyId"]
        kms_client.schedule_key_deletion(KeyId=key_id)
        result = kms_client.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "PendingDeletion"
        assert result["KeyMetadata"]["DeletionDate"]

        kms_client.cancel_key_deletion(KeyId=key_id)
        result = kms_client.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "Disabled"
        assert not result["KeyMetadata"].get("DeletionDate")

    @pytest.mark.aws_validated
    def test_disable_and_enable_key(self, kms_client, kms_create_key):
        key_id = kms_create_key()["KeyId"]
        result = kms_client.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is True
        assert result["KeyMetadata"]["KeyState"] == "Enabled"

        kms_client.disable_key(KeyId=key_id)
        result = kms_client.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is False
        assert result["KeyMetadata"]["KeyState"] == "Disabled"

        kms_client.enable_key(KeyId=key_id)
        result = kms_client.describe_key(KeyId=key_id)
        assert result["KeyMetadata"]["Enabled"] is True
        assert result["KeyMetadata"]["KeyState"] == "Enabled"

    # Not sure how useful this test is, as it just fails during key validation, before grant-specific logic kicks in.
    @pytest.mark.aws_validated
    def test_create_grant_with_invalid_key(self, kms_client, user_arn):

        with pytest.raises(botocore.exceptions.ClientError) as e:
            kms_client.create_grant(
                KeyId="invalid",
                GranteePrincipal=user_arn,
                Operations=["Decrypt", "Encrypt"],
            )
        e.match("NotFoundException")

    # Not sure how useful this test is, as it just fails during key validation, before grant-specific logic kicks in.
    @pytest.mark.aws_validated
    def test_list_grants_with_invalid_key(self, kms_client):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            kms_client.list_grants(
                KeyId="invalid",
            )
        e.match("NotFoundException")

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

    # Fails against AWS, as the retiring_principal_arn_prefix is invalid there.
    @pytest.mark.only_localstack
    def test_list_retirable_grants(self, kms_client, kms_create_key, kms_create_grant):
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
            response = kms_client.list_retirable_grants(
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
    def test_generate_data_key_pair_without_plaintext(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]
        result = kms_client.generate_data_key_pair_without_plaintext(
            KeyId=key_id, KeyPairSpec="RSA_2048"
        )
        assert result.get("PrivateKeyCiphertextBlob")
        assert "PrivateKeyPlaintext" not in result
        assert result.get("PublicKey")

    @pytest.mark.aws_validated
    def test_generate_data_key_pair(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]
        result = kms_client.generate_data_key_pair(KeyId=key_id, KeyPairSpec="RSA_2048")
        assert result.get("PrivateKeyCiphertextBlob")
        assert result.get("PrivateKeyPlaintext")
        assert result.get("PublicKey")

        # assert correct value of encrypted key
        decrypted = kms_client.decrypt(
            CiphertextBlob=result["PrivateKeyCiphertextBlob"], KeyId=key_id
        )
        assert decrypted["Plaintext"] == result["PrivateKeyPlaintext"]

    @pytest.mark.aws_validated
    def test_generate_data_key(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]
        # LocalStack currently doesn't act on KeySpec or on NumberOfBytes params, but one of them has to be set.
        result = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        assert result.get("CiphertextBlob")
        assert result.get("Plaintext")
        assert result.get("KeyId")

        # assert correct value of encrypted key
        decrypted = kms_client.decrypt(CiphertextBlob=result["CiphertextBlob"], KeyId=key_id)
        assert decrypted["Plaintext"] == result["Plaintext"]

    @pytest.mark.aws_validated
    def test_generate_data_key_without_plaintext(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]
        # LocalStack currently doesn't act on KeySpec or on NumberOfBytes params, but one of them has to be set.
        result = kms_client.generate_data_key_without_plaintext(KeyId=key_id, KeySpec="AES_256")
        assert result.get("CiphertextBlob")
        assert "Plaintext" not in result
        assert result.get("KeyId")

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("key_type", ["rsa", "ecc"])
    def test_sign_verify(self, kms_client, key_type, kms_create_key):
        key_spec = "RSA_2048" if key_type == "rsa" else "ECC_NIST_P256"
        result = kms_create_key(KeyUsage="SIGN_VERIFY", KeySpec=key_spec)
        key_id = result["KeyId"]

        message = b"test message 123 !%$@"
        algo = "RSASSA_PSS_SHA_256" if key_type == "rsa" else "ECDSA_SHA_256"
        kwargs = {"KeyId": key_id, "Message": message, "SigningAlgorithm": algo}
        signature = kms_client.sign(**kwargs)["Signature"]
        assert kms_client.verify(Signature=signature, **kwargs)["SignatureValid"]

    @pytest.mark.aws_validated
    def test_get_public_key(self, kms_client, kms_create_key):
        key = kms_create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="RSA_2048")
        response = kms_client.get_public_key(KeyId=key["KeyId"])
        assert response.get("KeyId") == key["Arn"]
        assert response.get("KeySpec") == key["KeySpec"]
        assert response.get("KeyUsage") == key["KeyUsage"]
        assert response.get("PublicKey")

    @pytest.mark.aws_validated
    def test_describe_and_list_sign_key(self, kms_client, kms_create_key):
        response = kms_create_key(KeyUsage="SIGN_VERIFY", CustomerMasterKeySpec="ECC_NIST_P256")

        key_id = response["KeyId"]
        describe_response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert describe_response["KeyId"] == key_id
        assert key_id in _get_all_key_ids(kms_client)

    @pytest.mark.aws_validated
    def test_import_key(self, kms_client, kms_create_key):
        key = kms_create_key(Origin="EXTERNAL")
        key_id = key["KeyId"]

        # get key import params
        params = kms_client.get_parameters_for_import(
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
        kms_client.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=encrypted_key,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )

        # use key to encrypt/decrypt data
        plaintext = b"test content 123 !#"
        encrypt_result = kms_client.encrypt(Plaintext=plaintext, KeyId=key_id)
        api_decrypted = kms_client.decrypt(
            CiphertextBlob=encrypt_result["CiphertextBlob"], KeyId=key_id
        )
        assert api_decrypted["Plaintext"] == plaintext

    @pytest.mark.aws_validated
    def test_list_aliases_of_key(self, kms_client, kms_create_key, kms_create_alias):
        aliased_key_id = kms_create_key()["KeyId"]
        comparison_key_id = kms_create_key()["KeyId"]

        alias_name = f"alias/{short_uid()}"
        kms_create_alias(AliasName=alias_name, TargetKeyId=aliased_key_id)

        assert _get_alias(kms_client, alias_name, aliased_key_id) is not None
        assert _get_alias(kms_client, alias_name, comparison_key_id) is None

    @pytest.mark.aws_validated
    def test_all_types_of_key_id_can_be_used_for_encryption(
        self, kms_client, kms_create_key, kms_create_alias
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
        alias_arn = get_alias_arn_by_alias_name(kms_client, alias_name)
        assert alias_arn
        kms_client.encrypt(KeyId=key_arn, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=key_id, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=alias_arn, Plaintext="encrypt-me")
        kms_client.encrypt(KeyId=alias_name, Plaintext="encrypt-me")

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
    def test_replicate_key(self, create_boto_client, kms_create_key, kms_replicate_key):
        region_to_replicate_from = "us-east-1"
        region_to_replicate_to = "us-west-1"
        from_region_client = create_boto_client("kms", region_to_replicate_from)
        to_region_client = create_boto_client("kms", region_to_replicate_to)

        key_id = kms_create_key(region=region_to_replicate_from, MultiRegion=True)["KeyId"]
        with pytest.raises(to_region_client.exceptions.NotFoundException):
            to_region_client.describe_key(KeyId=key_id)

        response = kms_replicate_key(
            region_from=region_to_replicate_from, KeyId=key_id, ReplicaRegion=region_to_replicate_to
        )
        assert response.get("ReplicaKeyMetadata")
        to_region_client.describe_key(KeyId=key_id)
        from_region_client.describe_key(KeyId=key_id)

    @pytest.mark.aws_validated
    def test_update_key_description(self, kms_client, kms_create_key):
        old_description = "old_description"
        new_description = "new_description"
        key = kms_create_key(Description=old_description)
        key_id = key["KeyId"]
        assert (
            kms_client.describe_key(KeyId=key_id)["KeyMetadata"]["Description"] == old_description
        )
        result = kms_client.update_key_description(KeyId=key_id, Description=new_description)
        assert "ResponseMetadata" in result
        assert (
            kms_client.describe_key(KeyId=key_id)["KeyMetadata"]["Description"] == new_description
        )

    @pytest.mark.aws_validated
    def test_key_rotation_status(self, kms_client, kms_key):
        key_id = kms_key["KeyId"]
        # According to AWS docs, supposed to be False by default.
        assert kms_client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is False
        kms_client.enable_key_rotation(KeyId=key_id)
        assert kms_client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is True
        kms_client.disable_key_rotation(KeyId=key_id)
        assert kms_client.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"] is False

    @pytest.mark.aws_validated
    def test_create_list_delete_alias(self, kms_client, kms_create_alias):
        alias_name = f"alias/{short_uid()}"
        assert _get_alias(kms_client, alias_name) is None
        kms_create_alias(AliasName=alias_name)
        assert _get_alias(kms_client, alias_name) is not None
        kms_client.delete_alias(AliasName=alias_name)
        assert _get_alias(kms_client, alias_name) is None

    @pytest.mark.aws_validated
    def test_update_alias(self, kms_client, kms_create_key, kms_create_alias):
        alias_name = f"alias/{short_uid()}"
        old_key_id = kms_create_key()["KeyId"]
        kms_create_alias(AliasName=alias_name, TargetKeyId=old_key_id)
        alias = _get_alias(kms_client, alias_name, old_key_id)
        assert alias is not None
        assert alias["TargetKeyId"] == old_key_id

        new_key_id = kms_create_key()["KeyId"]
        kms_client.update_alias(AliasName=alias_name, TargetKeyId=new_key_id)
        alias = _get_alias(kms_client, alias_name, new_key_id)
        assert alias is not None
        assert alias["TargetKeyId"] == new_key_id

    # Fails in AWS, as the principal is invalid there.
    # Maybe would work if get_aws_account_id() starts returning an actual AWS account ID.
    @pytest.mark.only_localstack
    def test_get_put_list_key_policies(self, kms_client, kms_create_key):
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
        response = kms_client.list_key_policies(KeyId=key_id)
        assert response.get("PolicyNames") == ["default"]
        assert response.get("Truncated") is False
        assert kms_client.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"] == policy_one
        kms_client.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy_two)
        assert kms_client.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"] == policy_two

    @pytest.mark.aws_validated
    def test_tag_untag_list_tags(self, kms_client, kms_create_key):
        def _create_tag(key):
            return {"TagKey": key, "TagValue": short_uid()}

        def _are_tags_there(tags, key_id):
            if not tags:
                return True
            next_token = None
            while True:
                kwargs = {"nextToken": next_token} if next_token else {}
                response = kms_client.list_resource_tags(KeyId=key_id, **kwargs)
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
        kms_client.tag_resource(KeyId=key_id, Tags=[new_tag_one, tag_three])
        assert _are_tags_there([new_tag_one, tag_two, tag_three], key_id) is True
        assert _are_tags_there([old_tag_one], key_id) is False
        kms_client.untag_resource(KeyId=key_id, TagKeys=[new_tag_one.get("TagKey")])
        assert _are_tags_there([tag_two, tag_three], key_id) is True
        assert _are_tags_there([new_tag_one], key_id) is False

    @pytest.mark.aws_validated
    def test_cant_use_disabled_or_deleted_keys(self, kms_client, kms_create_key):
        key_id = kms_create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")["KeyId"]
        kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")

        kms_client.disable_key(KeyId=key_id)
        with pytest.raises(botocore.exceptions.ClientError) as e:
            kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        e.match("DisabledException")

        kms_client.schedule_key_deletion(KeyId=key_id)
        with pytest.raises(botocore.exceptions.ClientError) as e:
            kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
        e.match("KMSInvalidStateException")

    @pytest.mark.aws_validated
    def test_cant_delete_deleted_key(self, kms_client, kms_create_key):
        key_id = kms_create_key()["KeyId"]
        kms_client.schedule_key_deletion(KeyId=key_id)

        with pytest.raises(botocore.exceptions.ClientError) as e:
            kms_client.schedule_key_deletion(KeyId=key_id)
        e.match("KMSInvalidStateException")
