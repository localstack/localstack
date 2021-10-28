import unittest
from urllib.parse import parse_qs

from moto.core.responses import BaseResponse

from localstack.utils.aws.aws_responses import parse_urlencoded_data


class TestMoto(unittest.TestCase):
    def test_request_parsing(self):
        qs = (
            "Action=PutMetricAlarm&Version=2010-08-01&ComparisonOperator=GreaterThanOrEqualToThreshold&"
            + "EvaluationPeriods=1&AlarmActions.member.1=test123&AlarmDescription=Upper+threshold+scaling+alarm&"
            + "Metrics.member.1.Expression=e1%2F%28%281000%2A30%2A60%29%2F100%29&Metrics.member.1.Id=expr_1&"
            + "Metrics.member.2.Expression=FILL%28m1%2C0%29&Metrics.member.2.Id=e1&"
            + "Metrics.member.2.ReturnData=false&Metrics.member.3.Id=m1&"
            + "Metrics.member.3.MetricStat.Metric.Dimensions.member.1.Name=StreamName&"
            + "Metrics.member.3.MetricStat.Metric.Dimensions.member.1.Value=arn%3Aaws%3Akinesis%3A123&"
            + "Metrics.member.3.MetricStat.Metric.MetricName=PutRecords.TotalRecords&"
            + "Metrics.member.3.MetricStat.Metric.Namespace=AWS%2FKinesis&Metrics.member.3.MetricStat.Period=60&"
            + "Metrics.member.3.MetricStat.Stat=Sum&Metrics.member.3.ReturnData=false&Threshold=80&"
            + "AlarmName=mctesterson-application-tests-kds-fastpipe-stack-dataops-None-e8f05d1a"
        )

        expected = [
            {"Expression": "e1/((1000*30*60)/100)", "Id": "expr_1"},
            {"Expression": "FILL(m1,0)", "Id": "e1", "ReturnData": "false"},
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {
                        "Dimensions.member": [
                            {"Name": "StreamName", "Value": "arn:aws:kinesis:123"}
                        ],
                        "MetricName": "PutRecords.TotalRecords",
                        "Namespace": "AWS/Kinesis",
                    },
                    "Period": "60",
                    "Stat": "Sum",
                },
                "ReturnData": "false",
            },
        ]

        response = BaseResponse()
        response.querystring = parse_qs(qs)
        result = response._get_multi_param("Metrics.member", skip_result_conversion=True)
        self.assertEqual(result, expected)

        # assert parsing via util
        result = parse_urlencoded_data(parse_qs(qs), "Metrics.member")
        self.assertEqual(result, expected)
