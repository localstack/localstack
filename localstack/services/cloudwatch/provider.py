from localstack.aws.api import RequestContext
from localstack.aws.api.cloudwatch import (
    AmazonResourceName,
    CloudwatchApi,
    ListTagsForResourceOutput,
    TagKeyList,
    TagList,
    TagResourceOutput,
    UntagResourceOutput,
)
from localstack.services.cloudwatch.cloudwatch_listener import TAGS


class CloudwatchProvider(CloudwatchApi):
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceOutput:
        tags = TAGS.list_tags_for_resource(resource_arn)
        return ListTagsForResourceOutput(Tags=tags.get("Tags", []))

    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        TAGS.untag_resource(resource_arn, tag_keys)
        return UntagResourceOutput()

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceOutput:
        TAGS.tag_resource(resource_arn, tags)
        return TagResourceOutput()
