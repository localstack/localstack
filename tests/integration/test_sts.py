import unittest
from base64 import b64encode

from localstack.utils.aws import aws_stack


class TestSTSIntegrations(unittest.TestCase):
    def setUp(self):
        self.sts_client = aws_stack.connect_to_service('sts')

    def test_assume_role(self):
        test_role_session_name = 's3-access-example'
        test_role_arn = 'arn:aws:sts::000000000000:role/rd_role'
        response = self.sts_client.assume_role(RoleArn=test_role_arn, RoleSessionName=test_role_session_name)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        if response['AssumedRoleUser']['AssumedRoleId']:
            assume_role_id_parts = response['AssumedRoleUser']['AssumedRoleId'].split(':')
            self.assertEqual(assume_role_id_parts[1], test_role_session_name)

    def test_assume_role_with_web_identity(self):
        test_role_session_name = 'web_token'
        test_role_arn = 'arn:aws:sts::000000000000:role/rd_role'
        test_web_identity_token = 'token'
        response = self.sts_client.assume_role_with_web_identity(RoleArn=test_role_arn,
                                                                 RoleSessionName=test_role_session_name,
                                                                 WebIdentityToken=test_web_identity_token)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        if response['AssumedRoleUser']['AssumedRoleId']:
            assume_role_id_parts = response['AssumedRoleUser']['AssumedRoleId'].split(':')
            self.assertEqual(assume_role_id_parts[1], test_role_session_name)

    def test_assume_role_with_saml(self):
        account_id = '000000000000'
        role_name = 'test-role'
        provider_name = 'TestProvFed'
        fed_name = 'testuser'

        saml_assertion = """
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
</samlp:Response>""".format(
            account_id=account_id,
            role_name=role_name,
            provider_name=provider_name,
            fed_name=fed_name,
        ).replace(
            '\n', ''
        )

        role_arn = 'arn:aws:iam::{account_id}:role/{role_name}' \
            .format(account_id=account_id, role_name=role_name)
        principal_arn = 'arn:aws:iam:{account_id}:saml-provider/{provider_name}' \
            .format(account_id=account_id, provider_name=provider_name)
        base64_saml_assertion = b64encode(saml_assertion.encode('utf-8')).decode('utf-8')
        response = self.sts_client.assume_role_with_saml(RoleArn=role_arn,
                                                         PrincipalArn=principal_arn,
                                                         SAMLAssertion=base64_saml_assertion)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        if response['AssumedRoleUser']['AssumedRoleId']:
            assume_role_id_parts = response['AssumedRoleUser']['AssumedRoleId'].split(':')
            self.assertEqual(assume_role_id_parts[1], fed_name)

    def test_get_federation_token(self):
        token_name = 'TestName'
        response = self.sts_client.get_federation_token(Name=token_name)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        self.assertTrue(response['Credentials']['SessionToken'])
        self.assertTrue(response['Credentials']['Expiration'])
        federated_user_info = response['FederatedUser']['FederatedUserId'].split(':')
        self.assertEqual(federated_user_info[1], token_name)
