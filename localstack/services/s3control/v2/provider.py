import datetime

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.s3control import (
    AccessPoint,
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
    NetworkOrigin,
    NonEmptyMaxLength1024String,
    NoSuchAccessPoint,
    NoSuchPublicAccessBlockConfiguration,
    Policy,
    PublicAccessBlockConfiguration,
    S3ControlApi,
    VpcConfiguration,
)
from localstack.services.s3.utils import validate_dict_fields
from localstack.services.s3control.v2.models import S3ControlStore, s3control_stores
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import short_uid
from localstack.utils.urls import localstack_host


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        if not message:
            message = "The XML you provided was not well-formed or did not validate against our published schema"
        super().__init__("MalformedXML", status_code=400, message=message)


class InvalidRequest(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidRequest", status_code=400, message=message)


FAKE_HOST_ID = "9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg="
PUBLIC_ACCESS_BLOCK_FIELDS = {
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
}
DEFAULT_ENDPOINTS = {
    "dualstack": f"s3-accesspoint.dualstack.<region>.{localstack_host()}",
    "fips": f"s3-accesspoint-fips.<region>.{localstack_host()}",
    "fips_dualstack": f"s3-accesspoint-fips.dualstack.<region>.{localstack_host()}",
    "ipv4": f"s3-accesspoint.<region>.{localstack_host()}",
}


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

        if not validate_dict_fields(
            public_access_block_configuration,
            required_fields=set(),
            optional_fields=PUBLIC_ACCESS_BLOCK_FIELDS,
        ):
            raise MalformedXML()

        if not public_access_block_configuration:
            raise InvalidRequest(
                "Must specify at least one configuration.",
            )

        for field in PUBLIC_ACCESS_BLOCK_FIELDS:
            if public_access_block_configuration.get(field) is None:
                public_access_block_configuration[field] = False

        store.public_access_block = public_access_block_configuration

    def get_public_access_block(
        self, context: RequestContext, account_id: AccountId
    ) -> GetPublicAccessBlockOutput:
        store = self.get_store(account_id, context.region)
        if not store.public_access_block:
            raise NoSuchPublicAccessBlockConfiguration(
                "The public access block configuration was not found",
                AccountId=account_id,
            )

        return GetPublicAccessBlockOutput(PublicAccessBlockConfiguration=store.public_access_block)

    def delete_public_access_block(self, context: RequestContext, account_id: AccountId) -> None:
        store = self.get_store(account_id, context.region)
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
        # TODO: support VpcConfiguration
        # TODO: support PublicAccessBlockConfiguration
        # TODO: check bucket_account_id
        # TODO: check if Bucket exists?
        # TODO: validate name, same as bucket with some more validation?
        # TODO: check if endpoint name already exists

        # TODO: access point might be region only?? test it
        store = self.get_store(account_id, context.region)

        # needs to be 32 long? maybe?
        # TODO: add to map?
        alias = f"{name}-{short_uid()}-s3alias"

        public_access_block_configuration = public_access_block_configuration or {}
        for field in PUBLIC_ACCESS_BLOCK_FIELDS:
            if public_access_block_configuration.get(field) is None:
                public_access_block_configuration[field] = True

        regional_endpoints = {
            t: endpoint.replace("<region>", context.region)
            for t, endpoint in DEFAULT_ENDPOINTS.items()
        }
        access_point_arn = f"arn:aws:s3:{context.region}:{account_id}:accesspoint/{name}"

        access_point = GetAccessPointResult(
            Name=name,
            Bucket=bucket,
            NetworkOrigin=NetworkOrigin.VPC if vpc_configuration else NetworkOrigin.Internet,
            PublicAccessBlockConfiguration=public_access_block_configuration,
            CreationDate=datetime.datetime.now(tz=datetime.UTC),
            Alias=alias,
            AccessPointArn=access_point_arn,
            Endpoints=regional_endpoints,
            BucketAccountId=bucket_account_id or account_id,  # TODO
        )
        if vpc_configuration:
            access_point["VpcConfiguration"] = vpc_configuration

        store.access_points[name] = access_point

        return CreateAccessPointResult(
            AccessPointArn=access_point_arn,
            Alias=alias,
        )

    def get_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> GetAccessPointResult:
        store = self.get_store(account_id, context.region)
        if not (access_point := store.access_points.get(name)):
            raise NoSuchAccessPoint(
                "The specified accesspoint does not exist",
                AccessPointName=name,
            )

        return access_point

    def list_access_points(
        self,
        context: RequestContext,
        account_id: AccountId,
        bucket: BucketName = None,
        next_token: NonEmptyMaxLength1024String = None,
        max_results: MaxResults = None,
    ) -> ListAccessPointsResult:
        # TODO: implement pagination
        # TODO: implement filter with Bucket name
        store = self.get_store(account_id, context.region)

        result = []
        for full_access_point in store.access_points.values():
            access_point: AccessPoint = select_from_typed_dict(AccessPoint, full_access_point)
            result.append(access_point)

        return ListAccessPointsResult(
            AccessPointList=result,
        )

    def delete_access_point(
        self, context: RequestContext, account_id: AccountId, name: AccessPointName
    ) -> None:
        store = self.get_store(account_id, context.region)
        if not store.access_points.pop(name, None):
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
