from localstack.aws.api import RequestContext
from localstack.aws.connect import connect_to
from localstack.services.resourcegroupstaggingapi.tagging.plugin import TaggingPlugin
from localstack.utils.aws.arns import parse_arn
from localstack.utils.aws.request_context import extract_access_key_id_from_auth_header

QUEUE_URL = "https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"


class SQSTaggingPlugin(TaggingPlugin):
    name = "sqs"

    @staticmethod
    def _get_sqs_client(context: RequestContext):
        access_key_id = extract_access_key_id_from_auth_header(dict(context.request.headers))
        return connect_to(region_name=context.region, aws_access_key_id=access_key_id).sqs

    @staticmethod
    def _queue_url_from_arn(arn: str):
        parsed_arn = parse_arn(arn)

        return QUEUE_URL.format(
            region=parsed_arn["region"],
            account_id=parsed_arn["account"],
            queue_name=parsed_arn["resource"],
        )

    def tag_resource(
        self, context: RequestContext, resource_arn: str, tags: dict[str, str]
    ) -> None:
        client = self._get_sqs_client(context)
        queue_url = self._queue_url_from_arn(resource_arn)
        client.tag_queue(QueueUrl=queue_url, Tags=tags)

    def untag_resource(self, context: RequestContext, resource_arn: str, tag_keys: list[str]):
        client = self._get_sqs_client(context)
        queue_url = self._queue_url_from_arn(resource_arn)
        client.untag_queue(QueueUrl=queue_url, TagKeys=tag_keys)
