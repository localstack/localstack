from localstack.aws.api import RequestContext
from localstack.aws.api.s3control import (
    AccountId,
    ListTagsForResourceResult,
    S3ControlApi,
    S3ResourceArn,
    Tag,
    TagKeyList,
    TagList,
    TagResourceResult,
    UntagResourceResult,
)
from localstack.services.s3.models import S3Store, s3_stores
from localstack.services.s3control.validation import validate_arn_for_tagging, validate_tags
from localstack.state import StateVisitor


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

        store = self.get_s3_store(account_id, context.region)
        store.tags.update_tags(resource_arn, {tag["Key"]: tag["Value"] for tag in tags})
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

        store = self.get_s3_store(account_id, context.region)
        store.tags.delete_tags(resource_arn, tag_keys)
        return TagResourceResult()

    def list_tags_for_resource(
        self, context: RequestContext, account_id: AccountId, resource_arn: S3ResourceArn, **kwargs
    ) -> ListTagsForResourceResult:
        # Currently S3Control only supports tagging buckets
        validate_arn_for_tagging(resource_arn, context.partition, account_id, context.region)

        store = self.get_s3_store(account_id, context.region)
        tags = store.tags.get_tags(resource_arn)
        return ListTagsForResourceResult(
            Tags=[Tag(Key=key, Value=value) for key, value in tags.items()]
        )
