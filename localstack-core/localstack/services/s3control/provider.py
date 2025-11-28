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
from localstack.aws.forwarder import NotImplementedAvoidFallbackError
from localstack.services.s3.models import s3_stores
from localstack.services.s3control.validation import validate_tags
from localstack.state import StateVisitor
from localstack.utils.tagging import TaggingService


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
    def _get_tagging_service_for_bucket(
        resource_arn: S3ResourceArn,
        partition: str,
        region: str,
        account_id: str,
    ) -> TaggingService:
        s3_prefix = f"arn:{partition}:s3:::"
        if not resource_arn.startswith(s3_prefix):
            # Moto does not support Tagging operations for S3 Control, so we should not forward those operations back
            # to it
            raise NotImplementedAvoidFallbackError(
                "LocalStack only support Bucket tagging operations for S3Control"
            )

        store = s3_stores[account_id][region]
        bucket_name = resource_arn.removeprefix(s3_prefix)
        if bucket_name not in store.global_bucket_map:
            raise NoSuchResource("The specified resource doesn't exist.")

        return store.TAGS

    def tag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tags: TagList,
        **kwargs,
    ) -> TagResourceResult:
        # currently S3Control only supports tagging buckets
        tagging_service = self._get_tagging_service_for_bucket(
            resource_arn=resource_arn,
            partition=context.partition,
            region=context.region,
            account_id=account_id,
        )

        validate_tags(tags=tags)
        tagging_service.tag_resource(resource_arn, tags)

        return TagResourceResult()

    def untag_resource(
        self,
        context: RequestContext,
        account_id: AccountId,
        resource_arn: S3ResourceArn,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResult:
        # currently S3Control only supports tagging buckets
        tagging_service = self._get_tagging_service_for_bucket(
            resource_arn=resource_arn,
            partition=context.partition,
            region=context.region,
            account_id=account_id,
        )

        tagging_service.untag_resource(resource_arn, tag_keys)

        return TagResourceResult()

    def list_tags_for_resource(
        self, context: RequestContext, account_id: AccountId, resource_arn: S3ResourceArn, **kwargs
    ) -> ListTagsForResourceResult:
        # currently S3Control only supports tagging buckets
        tagging_service = self._get_tagging_service_for_bucket(
            resource_arn=resource_arn,
            partition=context.partition,
            region=context.region,
            account_id=account_id,
        )

        tags = tagging_service.list_tags_for_resource(resource_arn)
        return ListTagsForResourceResult(Tags=tags["Tags"])
