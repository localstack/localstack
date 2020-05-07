import unittest
from localstack.utils.aws import aws_stack
from datetime import datetime, timedelta
from dateutil.tz import tzutc
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
