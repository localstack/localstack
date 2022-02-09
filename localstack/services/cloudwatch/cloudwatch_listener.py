from moto.cloudwatch.models import cloudwatch_backends

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws import aws_responses, aws_stack
from localstack.utils.common import parse_request_data
from localstack.utils.tagging import TaggingService

XMLNS_CLOUDWATCH = ""

# path for backdoor API to receive raw metrics
PATH_GET_RAW_METRICS = "/cloudwatch/metrics/raw"

TAGS = TaggingService()


class ProxyListenerCloudWatch(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if path.startswith(PATH_GET_RAW_METRICS):
            result = cloudwatch_backends[aws_stack.get_region()].metric_data
            result = [
                {
                    "ns": r.namespace,
                    "n": r.name,
                    "v": r.value,
                    "t": r.timestamp,
                    "d": [{"n": d.name, "v": d.value} for d in r.dimensions],
                }
                for r in result
            ]
            return {"metrics": result}
        return True

    def return_response(self, method, path, data, headers, response):

        req_data = parse_request_data(method, path, data)
        action = req_data.get("Action")
        if action == "PutMetricAlarm":
            name = req_data.get("AlarmName")
            # add missing attribute "TreatMissingData"
            treat_missing_data = req_data.get("TreatMissingData", "ignore")
            cloudwatch_backends[aws_stack.get_region()].alarms[
                name
            ].treat_missing_data = treat_missing_data
            # record tags
            arn = aws_stack.cloudwatch_alarm_arn(name)
            tags = aws_responses.extract_tags(req_data)
            TAGS.tag_resource(arn, tags)


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
