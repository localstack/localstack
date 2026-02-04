from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.s3control import (
    AccountId,
    ListTagsForResourceResult,
    S3ControlApi,
    S3ResourceArn,
    TagKeyList,
    TagList,
    TagResourceResult,
    UntagResourceResult,
)
from localstack.services.s3.models import S3Store, s3_stores
from localstack.services.s3control.validation import validate_arn_for_tagging, validate_tags
from localstack.state import StateVisitor


class NoSuchResource(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("NoSuchResource", status_code=404, message=message)


class S3ControlProvider(S3ControlApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.s3control.models import s3control_backends

        visitor.visit(s3control_backends)

    """
    S3Control is a management interface for S3, and can access some of its internals with no public API
    This requires us to access the s3 stores directly
    """

    @staticmethod
    def get_s3_store(account_id: str, region: str) -> S3Store:
        return s3_stores[account_id][region]

    def _tag_bucket_resource(
        self, resource_arn: str, partition: str, region: str, account_id: str, tags: TagList
    ) -> None:
        tagging_service = self.get_s3_store(account_id, region).TAGS
        tagging_service.tag_resource(resource_arn, tags)

    def _untag_bucket_resource(
        self, resource_arn: str, partition: str, region: str, account_id: str, tag_keys: TagKeyList
    ) -> None:
        tagging_service = self.get_s3_store(account_id, region).TAGS
        tagging_service.untag_resource(resource_arn, tag_keys)

    def _list_bucket_tags(
        self, resource_arn: str, partition: str, region: str, account_id: str
    ) -> TagList:
        tagging_service = self.get_s3_store(account_id, region).TAGS
        return tagging_service.list_tags_for_resource(resource_arn)["Tags"]

    def tag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tags: TagList,
        **kwargs,
    ) -> TagResourceResult:
        # Currently S3Control only supports tagging buckets
        validate_arn_for_tagging(resource_arn, context.partition, account_id, context.region)
        validate_tags(tags)

        self._tag_bucket_resource(resource_arn, context.partition, context.region, account_id, tags)
        return TagResourceResult()

    def untag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResult:
        # Currently S3Control only supports tagging buckets
        validate_arn_for_tagging(resource_arn, context.partition, account_id, context.region)

        self._untag_bucket_resource(
            resource_arn, context.partition, context.region, account_id, tag_keys
        )
        return TagResourceResult()

    def list_tags_for_resource(
        self, context: RequestContext, account_id: AccountId, resource_arn: S3ResourceArn, **kwargs
    ) -> ListTagsForResourceResult:
        # Currently S3Control only supports tagging buckets
        validate_arn_for_tagging(resource_arn, context.partition, account_id, context.region)

        tags = self._list_bucket_tags(resource_arn, context.partition, context.region, account_id)
        return ListTagsForResourceResult(Tags=tags)
