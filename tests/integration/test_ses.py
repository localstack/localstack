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
        
        # Should not fail after 2 consecutive tries
        client.list_templates()['TemplatesMetadata']
        templ_list = client.list_templates()['TemplatesMetadata']
        self.assertEqual(1, len(templ_list))

        template = templ_list[0]
        self.assertEqual(template['TemplateName'], TEST_TEMPLATE_ATTRIBUTES['TemplateName'])
        self.assertEqual(template['SubjectPart'], TEST_TEMPLATE_ATTRIBUTES['SubjectPart'])
        self.assertEqual(template['TextPart'], TEST_TEMPLATE_ATTRIBUTES['TextPart'])
        self.assertEqual(template['HtmlPart'], TEST_TEMPLATE_ATTRIBUTES['HtmlPart'])

        self.assertTrue(type(template['Timestamp']) is str)
        self.assertFalse(type(template['Timestamp']) is (date, datetime))

        # Validate Java SDKv2 Timestamp
        try:
            strptime_format = '%Y-%m-%dT%H:%M:%S.%fZ'
            datetime.strptime(template['Timestamp'], strptime_format)
        except ValueError:
            return False
