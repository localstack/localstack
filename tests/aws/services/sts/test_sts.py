# pyright: reportUnknownMemberType=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

import base64
import json
from base64 import b64encode

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.testing.aws.util import create_client_with_keys
from localstack.testing.config import TEST_AWS_ACCESS_KEY_ID
from localstack.testing.pytest import markers
from localstack.utils.aws.request_context import mock_aws_request_headers
from localstack.utils.numbers import is_number
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry

TEST_SAML_ASSERTION = """
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="_00000000-0000-0000-0000-000000000000" Version="2.0"
    IssueInstant="2012-01-01T12:00:00.000Z" Destination="https://signin.aws.amazon.com/saml"
    Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost/</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_00000000-0000-0000-0000-000000000000"
    IssueInstant="2012-12-01T12:00:00.000Z" Version="2.0">
    <Issuer>http://localhost:3000/</Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_00000000-0000-0000-0000-000000000000">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>
            NTIyMzk0ZGI4MjI0ZjI5ZGNhYjkyOGQyZGQ1NTZjODViZjk5YTY4ODFjOWRjNjkyYzZmODY2ZDQ4NjlkZjY3YSAgLQo=
          </ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>
        NTIyMzk0ZGI4MjI0ZjI5ZGNhYjkyOGQyZGQ1NTZjODViZjk5YTY4ODFjOWRjNjkyYzZmODY2ZDQ4NjlkZjY3YSAgLQo=
      </ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
            NTIyMzk0ZGI4MjI0ZjI5ZGNhYjkyOGQyZGQ1NTZjODViZjk5YTY4ODFjOWRjNjkyYzZmODY2ZDQ4NjlkZjY3YSAgLQo=
          </ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
      7ca82df9-1bad-4dd3-9b2b-adb68b554282
      </NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData
            NotOnOrAfter="2012-01-01T13:00:00.000Z"
            Recipient="https://signin.aws.amazon.com/saml"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2012-01-01T12:00:00.000Z" NotOnOrAfter="2012-01-01T13:00:00.000Z">
      <AudienceRestriction>
        <Audience>urn:amazon:webservices</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
        <AttributeValue>{fed_name}</AttributeValue>
      </Attribute>
      <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <AttributeValue>
            arn:aws:iam::{account_id}:saml-provider/{provider_name},arn:aws:iam::{account_id}:role/{role_name}
        </AttributeValue>
      </Attribute>
      <Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
        <AttributeValue>900</AttributeValue>
      </Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="2012-01-01T12:00:00.000Z" SessionIndex="_00000000-0000-0000-0000-000000000000">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>
"""


class TestSTSIntegrations:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..PackedPolicySize",
            "$..Role.Tags",  # Moto returns an empty list for no tags
        ],
    )
    def test_assume_role(self, aws_client, create_role, account_id, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.resource_name(),
                snapshot.transform.key_value("RoleId"),
                snapshot.transform.key_value("AccessKeyId"),
                snapshot.transform.key_value("SecretAccessKey"),
                snapshot.transform.key_value("SessionToken"),
            ]
        )
        snapshot.add_transformer(snapshot.transform.key_value("RoleSessionName"), priority=-1)

        test_role_session_name = f"test-assume-role-{short_uid()}"
        # we snapshot the test role session name with a transformer in order to validate its presence in the
        # `AssumedRoleId` and Àrn` of the `AssumedRoleUser`
        snapshot.match("role-session-name", {"RoleSessionName": test_role_session_name})
        test_role_name = f"role-{short_uid()}"
        assume_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": account_id},
                    "Effect": "Allow",
                }
            ],
        }
        created_role = create_role(
            RoleName=test_role_name, AssumeRolePolicyDocument=json.dumps(assume_policy_doc)
        )
        snapshot.match("create-role", created_role)

        def assume_role():
            assume_role_resp = aws_client.sts.assume_role(
                RoleArn=created_role["Role"]["Arn"], RoleSessionName=test_role_session_name
            )
            return assume_role_resp

        response = retry(assume_role, sleep=5, retries=4)
        snapshot.match("assume-role", response)

    @markers.aws.only_localstack
    def test_assume_non_existent_role(self, aws_client):
        test_role_session_name = "s3-access-example"
        test_role_arn = "arn:aws:sts::000000000000:role/rd_role"
        response = aws_client.sts.assume_role(
            RoleArn=test_role_arn, RoleSessionName=test_role_session_name
        )

        assert response["Credentials"]
        assert response["Credentials"]["SecretAccessKey"]
        if response["AssumedRoleUser"]["AssumedRoleId"]:
            assume_role_id_parts = response["AssumedRoleUser"]["AssumedRoleId"].split(":")
            assert assume_role_id_parts[1] == test_role_session_name

    @markers.aws.only_localstack
    def test_assume_role_with_web_identity(self, aws_client):
        test_role_session_name = "web_token"
        test_role_arn = "arn:aws:sts::000000000000:role/rd_role"
        test_web_identity_token = "token"
        response = aws_client.sts.assume_role_with_web_identity(
            RoleArn=test_role_arn,
            RoleSessionName=test_role_session_name,
            WebIdentityToken=test_web_identity_token,
        )

        assert response["Credentials"]
        assert response["Credentials"]["SecretAccessKey"]
        if response["AssumedRoleUser"]["AssumedRoleId"]:
            assume_role_id_parts = response["AssumedRoleUser"]["AssumedRoleId"].split(":")
            assert assume_role_id_parts[1] == test_role_session_name

    @markers.aws.only_localstack
    def test_assume_role_with_saml(self, aws_client):
        account_id = "000000000000"
        role_name = "test-role"
        provider_name = "TestProvFed"
        fed_name = "testuser"

        saml_assertion = TEST_SAML_ASSERTION.format(
            account_id=account_id,
            role_name=role_name,
            provider_name=provider_name,
            fed_name=fed_name,
        ).replace("\n", "")

        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        principal_arn = f"arn:aws:iam:{account_id}:saml-provider/{provider_name}"
        base64_saml_assertion = b64encode(saml_assertion.encode("utf-8")).decode("utf-8")
        response = aws_client.sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=base64_saml_assertion,
        )

        assert response["Credentials"]
        assert response["Credentials"]["SecretAccessKey"]
        if response["AssumedRoleUser"]["AssumedRoleId"]:
            assume_role_id_parts = response["AssumedRoleUser"]["AssumedRoleId"].split(":")
            assert assume_role_id_parts[1] == fed_name

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..PackedPolicySize"],
    )
    def test_get_federation_token(self, aws_client, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.resource_name(),
                snapshot.transform.key_value("AccessKeyId"),
                snapshot.transform.key_value("SecretAccessKey"),
                snapshot.transform.key_value("SessionToken"),
            ]
        )
        token_name = f"TestName{short_uid()}"
        response = aws_client.sts.get_federation_token(Name=token_name, DurationSeconds=900)
        snapshot.match("get-federation-token", response)

        federated_user_info = response["FederatedUser"]["FederatedUserId"].split(":")
        assert federated_user_info[1] == token_name

    @markers.aws.only_localstack
    def test_get_caller_identity_root(self, monkeypatch, aws_client):
        response = aws_client.sts.get_caller_identity()
        account_id = response["Account"]
        assert f"arn:aws:iam::{account_id}:root" == response["Arn"]

    @markers.aws.only_localstack
    def test_expiration_date_format(self, region_name):
        url = config.internal_service_url()
        data = {"Action": "GetSessionToken", "Version": "2011-06-15"}
        headers = mock_aws_request_headers(
            "sts",
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            region_name=region_name,
        )
        headers["Accept"] = APPLICATION_JSON
        response = requests.post(url, data=data, headers=headers)
        assert response
        content = json.loads(to_str(response.content))
        # Expiration field should be numeric (tested against AWS)
        result = content["GetSessionTokenResponse"]["GetSessionTokenResult"]
        assert is_number(result["Credentials"]["Expiration"])

    @markers.aws.only_localstack
    @pytest.mark.parametrize("use_aws_creds", [True, False])
    def test_get_caller_identity_user_access_key(
        self, cleanups, use_aws_creds, monkeypatch, region_name
    ):
        """Check whether the correct account id is returned for requests by other users access keys"""
        monkeypatch.setattr(config, "PARITY_AWS_ACCESS_KEY_ID", use_aws_creds)
        account_id = "123123123123"
        account_creds = {"AccessKeyId": account_id, "SecretAccessKey": "test"}
        iam_account_client = create_client_with_keys("iam", account_creds, region_name=region_name)
        user = iam_account_client.create_user(UserName=f"test-user-{short_uid()}")["User"]
        user_name = user["UserName"]
        user_arn = user["Arn"]
        cleanups.append(lambda: iam_account_client.delete_user(UserName=user_name))
        access_key_response = iam_account_client.create_access_key(UserName=user_name)["AccessKey"]
        cleanups.append(
            lambda: iam_account_client.delete_access_key(
                AccessKeyId=access_key_response["AccessKeyId"], UserName=user_name
            )
        )

        sts_user_client = create_client_with_keys(
            "sts", access_key_response, region_name=region_name
        )
        response = sts_user_client.get_caller_identity()
        assert account_id == response["Account"]
        assert user_arn == response["Arn"]

    @markers.aws.only_localstack
    @pytest.mark.parametrize("use_aws_creds", [True, False])
    def test_get_caller_identity_role_access_key(
        self, aws_client, account_id, cleanups, use_aws_creds, monkeypatch, region_name
    ):
        """Check whether the correct account id is returned for roles for other accounts"""
        monkeypatch.setattr(config, "PARITY_AWS_ACCESS_KEY_ID", use_aws_creds)
        fake_account_id = "123123123123"
        account_creds = {"AccessKeyId": fake_account_id, "SecretAccessKey": "test"}
        iam_account_client = create_client_with_keys("iam", account_creds, region_name=region_name)
        sts_account_client = create_client_with_keys("sts", account_creds, region_name=region_name)
        assume_policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": [account_id, fake_account_id]},
                    "Effect": "Allow",
                }
            ],
        }
        role_name = f"test-role-{short_uid()}"
        role_arn = iam_account_client.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_policy_doc)
        )["Role"]["Arn"]
        cleanups.append(lambda: iam_account_client.delete_role(RoleName=role_name))

        # assume the role and check if account id is correct
        assume_role_response = sts_account_client.assume_role(
            RoleArn=role_arn, RoleSessionName=f"test-session-{short_uid()}"
        )
        credentials = assume_role_response["Credentials"]
        sts_role_client = create_client_with_keys("sts", credentials, region_name=region_name)
        response = sts_role_client.get_caller_identity()
        assert fake_account_id == response["Account"]
        assert assume_role_response["AssumedRoleUser"]["Arn"] == response["Arn"]

        # assume the role coming from another account, to check if the account id is handled properly
        assume_role_response_other_account = aws_client.sts.assume_role(
            RoleArn=role_arn, RoleSessionName=f"test-session-{short_uid()}"
        )
        credentials_other_account = assume_role_response_other_account["Credentials"]
        sts_role_client_2 = create_client_with_keys(
            "sts", credentials_other_account, region_name=region_name
        )
        response = sts_role_client_2.get_caller_identity()
        assert fake_account_id == response["Account"]
        assert assume_role_response_other_account["AssumedRoleUser"]["Arn"] == response["Arn"]

    @markers.aws.validated
    def test_sts_invalid_parameters(
        self,
        aws_client_factory,
        snapshot,
    ):
        aws_client = aws_client_factory(config=Config(parameter_validation=False))
        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(RoleArn="nothing-valid-in-here", RoleSessionName="Session1")
        snapshot.match("malformed-arn", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn="arn::b:::something/test-role", RoleSessionName="Session1"
            )
        snapshot.match("no-partition", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn="arn:a::::something/test-role", RoleSessionName="Session1"
            )
        snapshot.match("no-service", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn="arn:a:::something/test-role", RoleSessionName="Session1"
            )
        snapshot.match("not-enough-colons", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(RoleArn="arn:a:a::aaaaaaaaaa:", RoleSessionName="Session1")
        snapshot.match("no-resource", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn="arn:a:b:::something/test-role", RoleSessionName="Session1:2"
            )
        snapshot.match("invalid-session-name", e.value.response)


class TestSTSWebIdentityToken:
    @markers.aws.validated
    def test_get_web_identity_token(self, aws_client, snapshot):
        """Test that GetWebIdentityToken returns a valid ES384 JWT."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
        )
        snapshot.match("get-web-identity-token-es384", response)

        token = response["WebIdentityToken"]
        # JWT must have 3 dot-separated parts
        parts = token.split(".")
        assert len(parts) == 3, f"Expected 3 JWT parts, got {len(parts)}"

        # Decode header and verify algorithm
        header_json = base64.urlsafe_b64decode(parts[0] + "==")
        header = json.loads(header_json)
        assert header["alg"] == "ES384"
        assert "kid" in header
        assert "aud" in header
        assert header["aud"] == "https://example.com"

    @markers.aws.validated
    def test_get_web_identity_token_rs256(self, aws_client, snapshot):
        """Test that GetWebIdentityToken returns a valid RS256 JWT."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="RS256",
        )
        snapshot.match("get-web-identity-token-rs256", response)

        token = response["WebIdentityToken"]
        parts = token.split(".")
        assert len(parts) == 3

        header_json = base64.urlsafe_b64decode(parts[0] + "==")
        header = json.loads(header_json)
        assert header["alg"] == "RS256"
        assert "kid" in header

    @markers.aws.validated
    def test_get_web_identity_token_invalid_algorithm(self, aws_client, snapshot):
        """Test that an unsupported algorithm raises ValidationError."""
        with pytest.raises(ClientError) as e:
            aws_client.sts.get_web_identity_token(
                Audience=["https://example.com"],
                SigningAlgorithm="RS384",
            )
        snapshot.match("invalid-algorithm", e.value.response)

    @markers.aws.validated
    def test_get_web_identity_token_default_duration(self, aws_client, snapshot):
        """Test that default duration is 300 seconds when DurationSeconds is omitted."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
        )
        snapshot.match("get-web-identity-token-default-duration", response)

        token = response["WebIdentityToken"]
        parts = token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)

        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] - payload["iat"] == 300

    @markers.aws.validated
    def test_get_web_identity_token_custom_duration(self, aws_client, snapshot):
        """Test GetWebIdentityToken with custom duration and ES384."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
            DurationSeconds=1800,
        )
        snapshot.match("get-web-identity-token-custom-duration", response)

        token = response["WebIdentityToken"]
        parts = token.split(".")
        assert len(parts) == 3

        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)
        assert payload["exp"] - payload["iat"] == 1800

    @markers.aws.validated
    def test_get_web_identity_token_invalid_duration(self, aws_client_factory, snapshot):
        """Test that out-of-range durations raise ValidationError."""
        aws_client = aws_client_factory(config=Config(parameter_validation=False))
        # Too low (below 60)
        with pytest.raises(ClientError) as e:
            aws_client.sts.get_web_identity_token(
                Audience=["https://example.com"],
                SigningAlgorithm="ES384",
                DurationSeconds=30,
            )
        snapshot.match("duration-too-low", e.value.response)

        # Too high (above 3600)
        with pytest.raises(ClientError) as e:
            aws_client.sts.get_web_identity_token(
                Audience=["https://example.com"],
                SigningAlgorithm="ES384",
                DurationSeconds=7200,
            )
        snapshot.match("duration-too-high", e.value.response)

    @markers.aws.validated
    def test_get_web_identity_token_claims(self, aws_client, account_id, snapshot):
        """Test that the JWT payload contains the expected claims."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
        )
        snapshot.match("get-web-identity-token-claims", response)

        token = response["WebIdentityToken"]
        parts = token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)

        assert "iss" in payload
        assert account_id in payload["iss"]
        assert "sub" in payload
        assert "aud" in payload
        assert payload["aud"] == "https://example.com"
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    @markers.aws.validated
    def test_get_web_identity_token_with_tags(self, aws_client, snapshot):
        """Test that tags are included in the JWT claims."""
        snapshot.add_transformer(
            snapshot.transform.key_value("WebIdentityToken", reference_replacement=False)
        )
        response = aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
            Tags=[{"Key": "env", "Value": "prod"}],
        )
        snapshot.match("get-web-identity-token-with-tags", response)

        token = response["WebIdentityToken"]
        parts = token.split(".")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_json)

        assert "tags" in payload
        assert payload["tags"] == {"env": "prod"}

    @markers.aws.only_localstack
    def test_jwks_endpoint(self, aws_client, account_id):
        """Test that the JWKS endpoint returns valid keys after token issuance."""
        # Issue an ES384 token to ensure the EC key is generated
        aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="ES384",
        )

        # Fetch the JWKS endpoint
        jwks_url = f"{config.internal_service_url()}/_aws/sts/{account_id}/.well-known/jwks.json"
        jwks_response = requests.get(jwks_url)
        assert jwks_response.status_code == 200
        jwks = jwks_response.json()

        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1

        # Find the EC key
        ec_keys = [k for k in jwks["keys"] if k.get("kty") == "EC"]
        assert len(ec_keys) == 1
        ec_key = ec_keys[0]
        assert ec_key["crv"] == "P-384"
        assert ec_key["alg"] == "ES384"
        assert ec_key["use"] == "sig"
        assert "kid" in ec_key
        assert "x" in ec_key
        assert "y" in ec_key

        # Also issue an RS256 token and verify RSA key appears in JWKS
        aws_client.sts.get_web_identity_token(
            Audience=["https://example.com"],
            SigningAlgorithm="RS256",
        )
        jwks_response = requests.get(jwks_url)
        assert jwks_response.status_code == 200
        jwks = jwks_response.json()

        rsa_keys = [k for k in jwks["keys"] if k.get("kty") == "RSA"]
        assert len(rsa_keys) == 1
        rsa_key = rsa_keys[0]
        assert rsa_key["alg"] == "RS256"
        assert rsa_key["use"] == "sig"
        assert "kid" in rsa_key
        assert "n" in rsa_key
        assert "e" in rsa_key

        # Both keys should now be present
        assert len(jwks["keys"]) >= 2


class TestSTSAssumeRoleTagging:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Role.Tags"]
    )  # Moto returns an empty list for no tags
    def test_iam_role_chaining_override_transitive_tags(
        self,
        aws_client,
        aws_client_factory,
        create_role,
        snapshot,
        region_name,
        account_id,
        wait_and_assume_role,
    ):
        snapshot.add_transformer(snapshot.transform.iam_api())
        role_name_1 = f"role-1-{short_uid()}"
        role_name_2 = f"role-2-{short_uid()}"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                    "Principal": {"AWS": account_id},
                }
            ],
        }

        role_1 = create_role(
            RoleName=role_name_1, AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        snapshot.match("role-1", role_1)
        role_2 = create_role(
            RoleName=role_name_2,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
        )
        snapshot.match("role-2", role_2)
        aws_client.iam.put_role_policy(
            RoleName=role_name_1,
            PolicyName=f"policy-{short_uid()}",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole", "sts:TagSession"],
                            "Resource": [role_2["Role"]["Arn"]],
                        }
                    ],
                }
            ),
        )

        # assume role 1 with transitive tags
        keys = wait_and_assume_role(
            role_arn=role_1["Role"]["Arn"],
            session_name="Session1",
            Tags=[{"Key": "SessionTag1", "Value": "SessionValue1"}],
            TransitiveTagKeys=["SessionTag1"],
        )
        role_1_clients = aws_client_factory(
            aws_access_key_id=keys["AccessKeyId"],
            aws_secret_access_key=keys["SecretAccessKey"],
            aws_session_token=keys["SessionToken"],
        )

        # try to assume role 2 by overriding transitive session tags
        with pytest.raises(ClientError) as e:
            role_1_clients.sts.assume_role(
                RoleArn=role_2["Role"]["Arn"],
                RoleSessionName="Session2SessionTagOverride",
                Tags=[{"Key": "SessionTag1", "Value": "SessionValue2"}],
            )
        snapshot.match("override-transitive-tag-error", e.value.response)

        # try to assume role 2 by overriding transitive session tags but with different casing
        with pytest.raises(ClientError) as e:
            role_1_clients.sts.assume_role(
                RoleArn=role_2["Role"]["Arn"],
                RoleSessionName="Session2SessionTagOverride",
                Tags=[{"Key": "sessiontag1", "Value": "SessionValue2"}],
            )
        snapshot.match("override-transitive-tag-case-ignore-error", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Role.Tags"]
    )  # Moto returns an empty list for no tags
    def test_assume_role_tag_validation(
        self,
        aws_client,
        aws_client_factory,
        create_role,
        snapshot,
        region_name,
        account_id,
        wait_and_assume_role,
    ):
        snapshot.add_transformer(snapshot.transform.iam_api())
        role_name_1 = f"role-1-{short_uid()}"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                    "Principal": {"AWS": account_id},
                }
            ],
        }

        role_1 = create_role(
            RoleName=role_name_1, AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        snapshot.match("role-1", role_1)

        # wait until role 1 is ready to be assumed
        wait_and_assume_role(
            role_arn=role_1["Role"]["Arn"],
            session_name="Session1",
        )
        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn=role_1["Role"]["Arn"],
                RoleSessionName="SessionInvalidTransitiveKeys",
                Tags=[{"Key": "SessionTag1", "Value": "SessionValue1"}],
                TransitiveTagKeys=["InvalidKey"],
            )
        snapshot.match("invalid-transitive-tag-keys", e.value.response)

        # transitive tags are case insensitive
        aws_client.sts.assume_role(
            RoleArn=role_1["Role"]["Arn"],
            RoleSessionName="SessionInvalidCasingTransitiveKeys",
            Tags=[{"Key": "SessionTag1", "Value": "SessionValue1"}],
            TransitiveTagKeys=["sessiontag1"],
        )

        # identical tags with different casing in key names are invalid
        with pytest.raises(ClientError) as e:
            aws_client.sts.assume_role(
                RoleArn=role_1["Role"]["Arn"],
                RoleSessionName="SessionInvalidCasingTransitiveKeys",
                Tags=[
                    {"Key": "SessionTag1", "Value": "SessionValue1"},
                    {"Key": "sessiontag1", "Value": "SessionValue2"},
                ],
                TransitiveTagKeys=["sessiontag1"],
            )
        snapshot.match("duplicate-tag-keys-different-casing", e.value.response)
