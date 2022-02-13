from moto.cloudwatch import cloudwatch_backends

from localstack.aws.api import HttpRequest, HttpResponse, RequestContext, handler
from localstack.aws.api.cloudwatch import (
    AmazonResourceName,
    CloudwatchApi,
    ListTagsForResourceOutput,
    PutMetricAlarmInput,
    TagKeyList,
    TagList,
    TagResourceOutput,
    UntagResourceOutput,
)
from localstack.services import moto
from localstack.utils.aws import aws_stack
from localstack.utils.tagging import TaggingService


class CloudwatchProvider(CloudwatchApi):
    def __init__(self):
        self.tags = TaggingService()

    def get_raw_metrics(self, request: HttpRequest, response: HttpResponse):
        region = aws_stack.extract_region_from_auth_header(request.headers)
        result = cloudwatch_backends[region].metric_data
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
        response.set_json({"metrics": result})

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceOutput:
        tags = self.tags.list_tags_for_resource(resource_arn)
        return ListTagsForResourceOutput(Tags=tags.get("Tags", []))

    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        self.tags.untag_resource(resource_arn, tag_keys)
        return UntagResourceOutput()

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceOutput:
        self.tags.tag_resource(resource_arn, tags)
        return TagResourceOutput()

    @handler("PutMetricAlarm", expand=False)
    def put_metric_alarm(
        self,
        context: RequestContext,
        request: PutMetricAlarmInput,
    ) -> None:
        moto.call_moto(context)

        name = request.get("AlarmName")
        arn = aws_stack.cloudwatch_alarm_arn(name)
        self.tags.tag_resource(arn, request.get("Tags"))
