from localstack import config
from localstack.services.infra import start_moto_server
import moto.cloudwatch.responses as cloudwatch_responses


def patch_lambda():

    if '<TreatMissingData>' not in cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE:
        cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE = cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE.replace(
            '</AlarmName>',
            '</AlarmName><TreatMissingData>{{ alarm.treat_missing_data }}</TreatMissingData>'
        )


def start_cloudwatch(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_CLOUDWATCH
    patch_lambda()
    return start_moto_server(
        'cloudwatch', port, name='CloudWatch',
        update_listener=update_listener, asynchronous=asynchronous
    )
