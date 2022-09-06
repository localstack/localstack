import json

import pytest

from localstack.utils.strings import short_uid


@pytest.mark.aws_validated
def test_alarm_creation(deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.resource_name())
    alarm_name = f"alarm-{short_uid()}"

    template = json.dumps(
        {
            "Resources": {
                "Alarm": {
                    "Type": "AWS::CloudWatch::Alarm",
                    "Properties": {
                        "AlarmName": alarm_name,
                        "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                        "EvaluationPeriods": 1,
                        "MetricName": "Errors",
                        "Namespace": "AWS/Lambda",
                        "Period": 300,
                        "Statistic": "Average",
                        "Threshold": 1,
                    },
                }
            },
            "Outputs": {
                "AlarmName": {"Value": {"Ref": "Alarm"}},
                "AlarmArnFromAtt": {"Value": {"Fn::GetAtt": "Alarm.Arn"}},
            },
        }
    )

    outputs = deploy_cfn_template(template=template).outputs
    snapshot.match("alarm_outputs", outputs)
