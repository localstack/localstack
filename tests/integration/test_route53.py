import unittest
from localstack.utils.aws import aws_stack


class TestRoute53(unittest.TestCase):

    def test_create_hosted_zone(self):
        route53 = aws_stack.connect_to_service('route53')

        response = route53.create_hosted_zone(Name='zone123', CallerReference='ref123')
        self.assertEqual(201, response['ResponseMetadata']['HTTPStatusCode'])

        # TODO implement
        # response = route53.get_change(Id='string')
