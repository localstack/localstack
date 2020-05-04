import unittest
from localstack.utils.aws import aws_stack
from datetime import datetime, timedelta


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

    def test_get_metric_data(self):

        conn = aws_stack.connect_to_service('cloudwatch')

        conn.put_metric_data(
            Namespace='some/thing', MetricData=[dict(MetricName='someMetric', Value=23)]
        )
        conn.put_metric_data(
            Namespace='some/thing', MetricData=[dict(MetricName='someMetric', Value=18)]
        )
        conn.put_metric_data(
            Namespace='ug/thing', MetricData=[dict(MetricName='ug', Value=23)]
        )

        # filtering metric data with current time interval
        response = conn.get_metric_data(
            MetricDataQueries=[{'Id': 'some', 'MetricStat': {'Metric':
                {'Namespace': 'some/thing', 'MetricName': 'someMetric'}, 'Period': 60, 'Stat': 'Sum'}},
                {'Id': 'part', 'MetricStat': {'Metric': {'Namespace': 'ug/thing', 'MetricName': 'ug'},
                'Period': 60, 'Stat': 'Sum'}}],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )

        self.assertEquals(len(response['MetricDataResults']), 2)

        for data_metric in response['MetricDataResults']:
            if data_metric['Id'] == 'some':
                self.assertEquals(data_metric['Values'][0], 41.0)
            if data_metric['Id'] == 'part':
                self.assertEquals(data_metric['Values'][0], 23.0)

        # filtering metric data with current time interval
        response = conn.get_metric_data(
            MetricDataQueries=[{'Id': 'some', 'MetricStat': {'Metric':
                {'Namespace': 'some/thing', 'MetricName': 'someMetric'}, 'Period': 60, 'Stat': 'Sum'}},
                {'Id': 'part', 'MetricStat': {'Metric': {'Namespace': 'ug/thing', 'MetricName': 'ug'},
                'Period': 60, 'Stat': 'Sum'}}],
            StartTime=datetime.utcnow() + timedelta(hours=1),
            EndTime=datetime.utcnow() + timedelta(hours=2),
        )

        for data_metric in response['MetricDataResults']:
            if data_metric['Id'] == 'some':
                self.assertEquals(len(data_metric['Values']), 0)
            if data_metric['Id'] == 'part':
                self.assertEquals(len(data_metric['Values']), 0)
