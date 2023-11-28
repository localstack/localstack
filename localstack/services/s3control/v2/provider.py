import datetime
import re
from random import choices
from string import ascii_lowercase, digits

from botocore.exceptions import ClientError

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
    InvalidURI,
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
from localstack.aws.connect import connect_to
from localstack.services.s3.utils import validate_dict_fields
from localstack.services.s3control.v2.models import S3ControlStore, s3control_stores
from localstack.utils.collections import select_from_typed_dict
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

ACCESS_POINT_REGEX = re.compile(r"^((?!xn--)(?!.*-s3alias$)[a-z0-9][a-z0-9-]{1,48}[a-z0-9])$")


class S3ControlProvider(S3ControlApi):
    """
    Lots of S3 Control API methods are related to S3 Outposts (S3 in your own datacenter)
    These are not implemented in this provider
    Access Points limitations:
    - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-restrictions-limitations.html
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
        # Access Point naming rules, see:
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-access-points.html#access-points-names

        # TODO: support VpcConfiguration
        # TODO: support PublicAccessBlockConfiguration
        # TODO: check bucket_account_id

        # TODO: access point might be region only?? test it
        store = self.get_store(account_id, context.region)
        if not ACCESS_POINT_REGEX.match(name):
            if len(name) < 3 or len(name) > 50 or "_" in name or name.isupper():
                raise InvalidURI(
                    "Couldn't parse the specified URI.",
                    URI=f"accesspoint/{name}",
                )

            raise InvalidRequest("Your Amazon S3 AccessPoint name is invalid")

        if name in store.access_points:
            # TODO: implement additional checks if the account id is different than the access point
            raise CommonServiceException(
                "AccessPointAlreadyOwnedByYou",
                "Your previous request to create the named accesspoint succeeded and you already own it.",
                status_code=409,
            )

        # TODO: what are the permissions to needed to create an AccessPoint to a bucket?
        try:
            connect_to(region_name=context.region).s3.head_bucket(Bucket=bucket)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "404":
                raise InvalidRequest(
                    "Amazon S3 AccessPoint can only be created for existing bucket",
                )
            # TODO: find AccessDenied exception?
            raise

        alias = create_random_alias(name)

        # if the PublicAccessBlockConfiguration is not set, then every field default to True
        # else, it's set to False
        is_pabc_none = public_access_block_configuration is None
        public_access_block_configuration = public_access_block_configuration or {}
        for field in PUBLIC_ACCESS_BLOCK_FIELDS:
            if public_access_block_configuration.get(field) is None:
                public_access_block_configuration[field] = is_pabc_none

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
        store.access_point_alias[alias] = bucket

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
        # TODO: implement ordering
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
            raise NoSuchAccessPoint(
                "The specified accesspoint does not exist",
                AccessPointName=name,
            )

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


def create_random_alias(name: str) -> str:
    return f"{name}-{''.join(choices(ascii_lowercase + digits, k=34))}-s3alias"
