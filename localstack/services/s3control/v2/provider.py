from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.s3control import (
    AccessPointName,
    AccountId,
    BucketName,
    CreateAccessPointResult,
    GetAccessPointPolicyResult,
    GetAccessPointPolicyStatusResult,
    GetAccessPointResult,
    GetPublicAccessBlockOutput,
    ListAccessPointsResult,
    MaxResults,
    NonEmptyMaxLength1024String,
    NoSuchPublicAccessBlockConfiguration,
    Policy,
    PublicAccessBlockConfiguration,
    S3ControlApi,
    VpcConfiguration,
)
from localstack.services.s3.utils import validate_dict_fields
from localstack.services.s3control.v2.models import S3ControlStore, s3control_stores


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        if not message:
            message = "The XML you provided was not well-formed or did not validate against our published schema"
        super().__init__("MalformedXML", status_code=400, message=message)


class InvalidRequest(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidRequest", status_code=400, message=message)


FAKE_HOST_ID = "9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg="


class S3ControlProvider(S3ControlApi):
    """
    Lots of S3 Control API methods are related to S3 Outposts (S3 in your own datacenter)
    These are not implemented in this provider
    """

    @staticmethod
    def get_store(account_id: str, region_name: str) -> S3ControlStore:
        return s3control_stores[account_id][region_name]

    def put_public_access_block(
        self,
        context: RequestContext,
        public_access_block_configuration: PublicAccessBlockConfiguration,
        account_id: AccountId,
    ) -> None:
        # TODO: do some check between passed account_id and context.account_id, but this is IAM realm
        # the region does not matter, everything is global
        store = self.get_store(account_id, context.region)

        public_access_block_fields = {
            "BlockPublicAcls",
            "BlockPublicPolicy",
            "IgnorePublicAcls",
            "RestrictPublicBuckets",
        }

        if not validate_dict_fields(
            public_access_block_configuration,
            required_fields=set(),
            optional_fields=public_access_block_fields,
        ):
            raise MalformedXML()

        if not public_access_block_configuration:
            raise InvalidRequest(
                "Must specify at least one configuration.",
            )

        for field in public_access_block_fields:
            if public_access_block_configuration.get(field) is None:
                public_access_block_configuration[field] = False

        store.public_access_block = public_access_block_configuration

    def get_public_access_block(
        self, context: RequestContext, account_id: AccountId
    ) -> GetPublicAccessBlockOutput:
        store = self.get_store(context.account_id, context.region)
        if not store.public_access_block:
            raise NoSuchPublicAccessBlockConfiguration(
                "The public access block configuration was not found",
                AccountId=account_id,
            )

        return GetPublicAccessBlockOutput(PublicAccessBlockConfiguration=store.public_access_block)

    def delete_public_access_block(self, context: RequestContext, account_id: AccountId) -> None:
        store = self.get_store(context.account_id, context.region)
        store.public_access_block = None

    def create_access_point(
        self,
        context: RequestContext,
        account_id: AccountId,
        name: AccessPointName,
        bucket: BucketName,
        vpc_configuration: VpcConfiguration = None,
        public_access_block_configuration: PublicAccessBlockConfiguration = None,
        bucket_account_id: AccountId = None,
    ) -> CreateAccessPointResult:
        pass

    def get_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointResult:
        pass

    def list_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName = None,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
    ) -> ListAccessPointsResult:
        pass

    def delete_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> None:
        pass

    def put_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName, policy: Policy
    ) -> None:
        pass

    def get_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointPolicyResult:
        pass

    def delete_access_point_policy(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> None:
        pass

    def get_access_point_policy_status(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointPolicyStatusResult:
        pass
