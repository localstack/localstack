import moto.cloudwatch.responses as cloudwatch_responses

from localstack import config
from localstack.services.infra import start_moto_server


def apply_patches():

    if "<TreatMissingData>" not in cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE:
        cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE = (
            cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE.replace(
                "</AlarmName>",
                "</AlarmName><TreatMissingData>{{ alarm.treat_missing_data }}</TreatMissingData>",
            )
        )

    # add put_composite_alarm

    def put_composite_alarm(self):
        return self.put_metric_alarm()

    if not hasattr(cloudwatch_responses.CloudWatchResponse, "put_composite_alarm"):
        cloudwatch_responses.CloudWatchResponse.put_composite_alarm = put_composite_alarm


def start_cloudwatch(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_CLOUDWATCH
    apply_patches()
    return start_moto_server(
        "cloudwatch",
        port,
        name="CloudWatch",
        update_listener=update_listener,
        asynchronous=asynchronous,
    )
