import unittest

from datetime import datetime
from dateutil.tz import tzutc

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class CloudWatchTest(unittest.TestCase):
    def test_put_metric_data(self):
        metric_name = 'metric-%s' % short_uid()
        namespace = 'namespace-%s' % short_uid()

        client = aws_stack.connect_to_service('cloudwatch')

        # Put metric data without value
        data = [
            {
                'MetricName': metric_name,
                'Dimensions': [{
                    'Name': 'foo',
                    'Value': 'bar'
                }],
                'Timestamp': datetime(2019, 1, 3, tzinfo=tzutc()),
                'Unit': 'Seconds'
            }
        ]
        rs = client.put_metric_data(
            Namespace=namespace,
            MetricData=data
        )
        self.assertEquals(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        # Get metric statistics
        rs = client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=datetime(2019, 1, 1),
            EndTime=datetime(2019, 1, 10),
            Period=120,
            Statistics=[
                'Average'
            ]
        )
        self.assertEqual(rs['Label'], metric_name)
        self.assertEqual(len(rs['Datapoints']), 1)
        self.assertEqual(rs['Datapoints'][0]['Timestamp'], data[0]['Timestamp'])

        rs = client.list_metrics(
            Namespace=namespace,
            MetricName=metric_name
        )
        self.assertEqual(len(rs['Metrics']), 1)
        self.assertEqual(rs['Metrics'][0]['Namespace'], namespace)
