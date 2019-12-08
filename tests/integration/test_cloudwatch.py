import unittest
from localstack.utils.aws import aws_stack


class CloudWatchTest(unittest.TestCase):

    def test_put_metric_data(self):
        client = aws_stack.connect_to_service('cloudwatch')

        data = [
            {
                'MetricName': 'm1',
                'Dimensions': [{
                    'Name': 'foo',
                    'Value': 'bar'
                }],
                'Value': 123.45,
                'StatisticValues': {
                    'SampleCount': 123.0,
                    'Sum': 123.0,
                    'Minimum': 123.0,
                    'Maximum': 123.0
                },
                'Values': [
                    123.0,
                ],
                'Counts': [
                    123.0,
                ],
                'Unit': 'Seconds',
                'StorageResolution': 123
            },
        ]
        response = client.put_metric_data(Namespace='string', MetricData=data)
        self.assertEquals(response['ResponseMetadata']['HTTPStatusCode'], 200)
