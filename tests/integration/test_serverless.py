import os
import json
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import run


class TestServerless(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        base_dir = os.path.join(os.path.dirname(__file__), 'serverless')

        if not os.path.exists(os.path.join(base_dir, 'node_modules')):
            # install dependencies
            run('cd %s; npm install' % base_dir)

        # deploy serverless app
        run('cd %s; npm run serverless -- --region=%s' % (base_dir, aws_stack.get_region()))

    def test_event_rules_deployed(self):
        events = aws_stack.connect_to_service('events')
        rules = events.list_rules()['Rules']
        rule = ([r for r in rules if r['Name'] == 'sls-test-cf-event'] or [None])[0]
        self.assertTrue(rule)
        self.assertIn('Arn', rule)
        pattern = json.loads(rule['EventPattern'])
        self.assertEqual(pattern['source'], ['aws.cloudformation'])
        self.assertIn('detail-type', pattern)
