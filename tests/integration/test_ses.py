import json
import os
import unittest
from datetime import date, datetime

import localstack.config as config
from localstack.utils.aws import aws_stack

TEST_TEMPLATE_ATTRIBUTES = {
    'TemplateName': 'hello-world',
    'SubjectPart': 'Subject test',
    'TextPart': 'hello\nworld',
    'HtmlPart': 'hello<br/>world',
}


class SESTest(unittest.TestCase):

    def test_list_templates(self):
        client = aws_stack.connect_to_service('ses')
        client.create_template(Template=TEST_TEMPLATE_ATTRIBUTES)
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(1, len(templ_list))
        created_template = templ_list[0]
        self.assertEqual(TEST_TEMPLATE_ATTRIBUTES['TemplateName'], created_template['Name'])
        self.assertIn(type(created_template['CreatedTimestamp']), (date, datetime))

        # Should not fail after 2 consecutive tries
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(1, len(templ_list))
        created_template = templ_list[0]
        self.assertEqual(TEST_TEMPLATE_ATTRIBUTES['TemplateName'], created_template['Name'])
        self.assertIn(type(created_template['CreatedTimestamp']), (date, datetime))

    def test_delete_template(self):
        client = aws_stack.connect_to_service('ses')
        client.create_template(Template=TEST_TEMPLATE_ATTRIBUTES)
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(1, len(templ_list))
        client.delete_template(TemplateName=TEST_TEMPLATE_ATTRIBUTES['TemplateName'])
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(0, len(templ_list))

    def test_get_identity_verification_attributes(self):
        client = aws_stack.connect_to_service('ses')
        domain = 'example.com'
        email = 'user@example.com'
        test_values = [domain, email]
        response = client.get_identity_verification_attributes(Identities=test_values)['VerificationAttributes']
        self.assertEqual(2, len(response))
        for value in test_values:
            self.assertEqual('Success', response[value]['VerificationStatus'])
        self.assertIn('VerificationToken', response[domain])
        self.assertNotIn('VerificationToken', response[email])

    def test_send_email_save(self):
        client = aws_stack.connect_to_service('ses')
        data_dir = config.DATA_DIR or config.TMP_FOLDER
        email = 'user@example.com'
        client.verify_email_address(EmailAddress=email)
        message = client.send_email(
            Source=email,
            Message={
                'Subject': {
                    'Data': 'A_SUBJECT',
                },
                'Body': {
                    'Text': {
                        'Data': 'A_MESSAGE',
                    },
                },
            },
            Destination={
                'ToAddresses': ['success@example.com'],
            }
        )

        with open(os.path.join(data_dir, 'ses', message['MessageId'] + '.json'), 'r') as f:
            message = f.read()

        contents = json.loads(message)
        self.assertEqual(email, contents['Source'])
        self.assertEqual('A_SUBJECT', contents['Subject'])
        self.assertEqual('A_MESSAGE', contents['Body'])
        self.assertEqual(['success@example.com'], contents['Destinations']['ToAddresses'])
