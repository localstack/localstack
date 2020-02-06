import re
import unittest
from localstack.utils.cloudformation import template_deployer


class CloudFormationTest(unittest.TestCase):

    def test_resolve_references(self):
        ref = {
            'Fn::Join': ['',
                ['arn:', {'Ref': 'AWS::Partition'}, ':apigateway:',
                {'Ref': 'AWS::Region'}, ':lambda:path/2015-03-31/functions/',
                'test:lambda:arn', '/invocations']
            ]
        }
        stack_name = 'test'
        resources = {}
        result = template_deployer.resolve_refs_recursively(stack_name, ref, resources)
        pattern = r'arn:aws:apigateway:.*:lambda:path/2015-03-31/functions/test:lambda:arn/invocations'
        self.assertTrue(re.match(pattern, result))
