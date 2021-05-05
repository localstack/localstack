import unittest

from datetime import date, datetime
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
        self.assertEqual(created_template['Name'], TEST_TEMPLATE_ATTRIBUTES['TemplateName'])
        self.assertIn(type(created_template['CreatedTimestamp']), (date, datetime))

        # Should not fail after 2 consecutive tries
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(1, len(templ_list))
        created_template = templ_list[0]
        self.assertEqual(created_template['Name'], TEST_TEMPLATE_ATTRIBUTES['TemplateName'])
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
