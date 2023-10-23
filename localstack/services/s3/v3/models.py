import hashlib
import logging
from collections import defaultdict
from datetime import datetime
from secrets import token_urlsafe
from typing import Literal, NamedTuple, Optional, Union

from zoneinfo import ZoneInfo

from localstack import config
from localstack.aws.api import CommonServiceException
from localstack.aws.api.s3 import (
    AccessControlPolicy,
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    BucketAccelerateStatus,
    BucketKeyEnabled,
    BucketName,
    BucketRegion,
    BucketVersioningStatus,
    ChecksumAlgorithm,
    CompletedPartList,
    CORSConfiguration,
    DefaultRetention,
    EntityTooSmall,
    ETag,
    Expiration,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InvalidArgument,
    InvalidPart,
    InventoryConfiguration,
    InventoryId,
    LifecycleRules,
    LoggingEnabled,
    Metadata,
    MethodNotAllowed,
    MultipartUploadId,
    NoSuchKey,
    NoSuchVersion,
    NotificationConfiguration,
    ObjectKey,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectLockRetainUntilDate,
    ObjectLockRetentionMode,
    ObjectOwnership,
    ObjectStorageClass,
    ObjectVersionId,
    Owner,
    PartNumber,
    Payer,
    Policy,
    PublicAccessBlockConfiguration,
    ReplicationConfiguration,
    Restore,
    ServerSideEncryption,
    ServerSideEncryptionRule,
    Size,
    SSEKMSKeyId,
    StorageClass,
    WebsiteConfiguration,
    WebsiteRedirectLocation,
)
from localstack.services.s3.constants import (
    DEFAULT_BUCKET_ENCRYPTION,
    DEFAULT_PUBLIC_BLOCK_ACCESS,
    S3_UPLOAD_PART_MIN_SIZE,
)
from localstack.services.s3.utils import (
    iso_8601_datetime_without_milliseconds_s3,
    rfc_1123_datetime,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws import arns
from localstack.utils.tagging import TaggingService

# TODO: beware of timestamp data, we need the snapshot to be more precise for S3, with the different types
# moto had a lot of issue with it? not sure about our parser/serializer

LOG = logging.getLogger(__name__)

_gmt_zone_info = ZoneInfo("GMT")


# note: not really a need to use a dataclass here, as it has a lot of fields, but only a few are set at creation
class S3Bucket:
    name: BucketName
    bucket_account_id: AccountId
    bucket_region: BucketRegion
    creation_date: datetime
    multiparts: dict[MultipartUploadId, "S3Multipart"]
    objects: Union["KeyStore", "VersionedKeyStore"]
    versioning_status: BucketVersioningStatus | None
    lifecycle_rules: Optional[LifecycleRules]
    policy: Optional[Policy]
    website_configuration: Optional[WebsiteConfiguration]
    acl: AccessControlPolicy
    cors_rules: Optional[CORSConfiguration]
    logging: LoggingEnabled
    notification_configuration: NotificationConfiguration
    payer: Payer
    encryption_rule: Optional[ServerSideEncryptionRule]
    public_access_block: Optional[PublicAccessBlockConfiguration]
    accelerate_status: Optional[BucketAccelerateStatus]
    object_lock_enabled: bool
    object_ownership: ObjectOwnership
    intelligent_tiering_configurations: dict[IntelligentTieringId, IntelligentTieringConfiguration]
    analytics_configurations: dict[AnalyticsId, AnalyticsConfiguration]
    inventory_configurations: dict[InventoryId, InventoryConfiguration]
    object_lock_default_retention: Optional[DefaultRetention]
    replication: ReplicationConfiguration
    owner: Owner

    # set all buckets parameters here
    def __init__(
        self,
        name: BucketName,
        account_id: AccountId,
        bucket_region: BucketRegion,
        owner: Owner,
        acl: AccessControlPolicy = None,
        object_ownership: ObjectOwnership = None,
        object_lock_enabled_for_bucket: bool = None,
    ):
        self.name = name
        self.bucket_account_id = account_id
        self.bucket_region = bucket_region
        # If ObjectLock is enabled, it forces the bucket to be versioned as well
        self.versioning_status = None if not object_lock_enabled_for_bucket else "Enabled"
        self.objects = KeyStore() if not object_lock_enabled_for_bucket else VersionedKeyStore()
        self.object_ownership = object_ownership or ObjectOwnership.BucketOwnerEnforced
        self.object_lock_enabled = object_lock_enabled_for_bucket
        self.encryption_rule = DEFAULT_BUCKET_ENCRYPTION
        self.creation_date = datetime.now(tz=_gmt_zone_info)
        self.payer = Payer.BucketOwner
        self.public_access_block = DEFAULT_PUBLIC_BLOCK_ACCESS
        self.multiparts = {}
        self.notification_configuration = {}
        self.logging = {}
        self.cors_rules = None
        self.lifecycle_rules = None
        self.website_configuration = None
        self.policy = None
        self.accelerate_status = None
        self.intelligent_tiering_configurations = {}
        self.analytics_configurations = {}
        self.inventory_configurations = {}
        self.object_lock_default_retention = {}
        self.replication = None
        self.acl = acl
        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
        self.owner = owner
        self.bucket_arn = arns.s3_bucket_arn(self.name)

    def get_object(
        self,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        http_method: Literal["GET", "PUT", "HEAD", "DELETE"] = "GET",
        raise_for_delete_marker: bool = True,
    ) -> Union["S3Object", "S3DeleteMarker"]:
        """
        :param key: the Object Key
        :param version_id: optional, the versionId of the object
        :param http_method: the HTTP method of the original call. This is necessary for the exception if the bucket is
        versioned or suspended
        see: https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html
        :param raise_for_delete_marker: optional, indicates if the method should raise an exception if the found object
        is a S3DeleteMarker. If False, it can return a S3DeleteMarker
        :return:
        :raises NoSuchKey if the object key does not exist at all, or if the object is a DeleteMarker
        :raises MethodNotAllowed if the object is a DeleteMarker and the operation is not allowed against it
        """

        if self.versioning_status is None:
            if version_id and version_id != "null":
                raise InvalidArgument(
                    "Invalid version id specified",
                    ArgumentName="versionId",
                    ArgumentValue=version_id,
                )

            s3_object = self.objects.get(key)

            if not s3_object:
                raise NoSuchKey("The specified key does not exist.", Key=key)

        else:
            self.objects: VersionedKeyStore
            if version_id:
                s3_object_version = self.objects.get(key, version_id)
                if not s3_object_version:
                    raise NoSuchVersion(
                        "The specified version does not exist.",
                        Key=key,
                        VersionId=version_id,
                    )
                elif raise_for_delete_marker and isinstance(s3_object_version, S3DeleteMarker):
                    if http_method == "HEAD":
                        raise CommonServiceException(
                            code="405",
                            message="Method Not Allowed",
                            status_code=405,
                        )

                    raise MethodNotAllowed(
                        "The specified method is not allowed against this resource.",
                        Method=http_method,
                        ResourceType="DeleteMarker",
                        DeleteMarker=True,
                        Allow="DELETE",
                        VersionId=s3_object_version.version_id,
                    )
                return s3_object_version

            s3_object = self.objects.get(key)

            if not s3_object:
                raise NoSuchKey("The specified key does not exist.", Key=key)

            elif raise_for_delete_marker and isinstance(s3_object, S3DeleteMarker):
                if http_method not in ("HEAD", "GET"):
                    raise MethodNotAllowed(
                        "The specified method is not allowed against this resource.",
                        Method=http_method,
                        ResourceType="DeleteMarker",
                        DeleteMarker=True,
                        Allow="DELETE",
                        VersionId=s3_object.version_id,
                    )

                raise NoSuchKey(
                    "The specified key does not exist.",
                    Key=key,
                    DeleteMarker=True,
                    VersionId=s3_object.version_id,
                )

        return s3_object


# note: might be migrated to dataclass once the full API is set
class S3Object:
    key: ObjectKey
    version_id: Optional[ObjectVersionId]
    bucket: BucketName
    owner: Optional[Owner]
    size: Optional[Size]
    etag: Optional[ETag]
    user_metadata: Metadata
    system_metadata: Metadata
    last_modified: datetime
    expires: Optional[datetime]
    expiration: Optional[Expiration]  # right now, this is stored in the provider cache
    storage_class: StorageClass | ObjectStorageClass
    encryption: Optional[ServerSideEncryption]  # inherit bucket
    kms_key_id: Optional[SSEKMSKeyId]  # inherit bucket
    bucket_key_enabled: Optional[bool]  # inherit bucket
    checksum_algorithm: ChecksumAlgorithm
    checksum_value: str
    lock_mode: Optional[ObjectLockMode | ObjectLockRetentionMode]
    lock_legal_status: Optional[ObjectLockLegalHoldStatus]
    lock_until: Optional[datetime]
    website_redirect_location: Optional[WebsiteRedirectLocation]
    acl: Optional[AccessControlPolicy]
    is_current: bool
    parts: Optional[dict[int, tuple[int, int]]]
    restore: Optional[Restore]

    def __init__(
        self,
        key: ObjectKey,
        etag: Optional[ETag] = None,
        size: Optional[int] = None,
        version_id: Optional[ObjectVersionId] = None,
        user_metadata: Optional[Metadata] = None,
        system_metadata: Optional[Metadata] = None,
        storage_class: StorageClass = StorageClass.STANDARD,
        expires: Optional[datetime] = None,
        expiration: Optional[Expiration] = None,
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        checksum_value: Optional[str] = None,
        encryption: Optional[ServerSideEncryption] = None,
        kms_key_id: Optional[SSEKMSKeyId] = None,
        bucket_key_enabled: bool = False,
        lock_mode: Optional[ObjectLockMode | ObjectLockRetentionMode] = None,
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,
        lock_until: Optional[datetime] = None,
        website_redirect_location: Optional[WebsiteRedirectLocation] = None,
        acl: Optional[AccessControlPolicy] = None,  # TODO
        owner: Optional[Owner] = None,
    ):
        self.key = key
        self.user_metadata = (
            {k.lower(): v for k, v in user_metadata.items()} if user_metadata else {}
        )
        self.system_metadata = system_metadata or {}
        self.version_id = version_id
        self.storage_class = storage_class or StorageClass.STANDARD
        self.etag = etag
        self.size = size
        self.expires = expires
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        self.encryption = encryption
        self.kms_key_id = kms_key_id
        self.bucket_key_enabled = bucket_key_enabled
        self.lock_mode = lock_mode
        self.lock_legal_status = lock_legal_status
        self.lock_until = lock_until
        self.acl = acl
        self.expiration = expiration
        self.website_redirect_location = website_redirect_location
        self.is_current = True
        self.last_modified = datetime.now(tz=_gmt_zone_info)
        self.parts = {}
        self.restore = None
        self.owner = owner

    def get_system_metadata_fields(self) -> dict:
        headers = {
            "LastModified": self.last_modified_rfc1123,
            "ContentLength": str(self.size),
            "ETag": self.quoted_etag,
        }
        if self.expires:
            headers["Expires"] = self.expires_rfc1123

        for metadata_key, metadata_value in self.system_metadata.items():
            headers[metadata_key] = metadata_value

        # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested)
        if "ContentEncoding" not in headers and self.checksum_algorithm:
            headers["ContentEncoding"] = ""

        if self.storage_class != StorageClass.STANDARD:
            headers["StorageClass"] = self.storage_class

        return headers

    @property
    def last_modified_iso8601(self) -> str:
        # TODO: verify if we need them with proper snapshot testing, for now it's copied from moto
        return iso_8601_datetime_without_milliseconds_s3(self.last_modified)  # type: ignore

    @property
    def last_modified_rfc1123(self) -> str:
        # TODO: verify if we need them with proper snapshot testing, for now it's copied from moto
        # Different datetime formats depending on how the key is obtained
        # https://github.com/boto/boto/issues/466
        return rfc_1123_datetime(self.last_modified)

    @property
    def expires_rfc1123(self) -> str:
        return rfc_1123_datetime(self.expires)

    @property
    def quoted_etag(self) -> str:
        return f'"{self.etag}"'

    def is_locked(self, bypass_governance: bool = False) -> bool:
        if self.lock_legal_status == "ON":
            return True

        if bypass_governance and self.lock_mode == ObjectLockMode.GOVERNANCE:
            return False

        if self.lock_until:
            return self.lock_until > datetime.now(tz=_gmt_zone_info)

        return False


# TODO: could use dataclass, validate after models are set
class S3DeleteMarker:
    key: ObjectKey
    version_id: str
    last_modified: datetime
    is_current: bool

    def __init__(self, key: ObjectKey, version_id: ObjectVersionId):
        self.key = key
        self.version_id = version_id
        self.last_modified = datetime.now(tz=_gmt_zone_info)
        self.is_current = True

    @staticmethod
    def is_locked(*args, **kwargs) -> bool:
        # an S3DeleteMarker cannot be lock protected
        return False


# TODO: could use dataclass, validate after models are set
class S3Part:
    part_number: PartNumber
    etag: Optional[ETag]
    last_modified: datetime
    size: Optional[int]
    checksum_algorithm: Optional[ChecksumAlgorithm]
    checksum_value: Optional[str]

    def __init__(
        self,
        part_number: PartNumber,
        size: int = None,
        etag: ETag = None,
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        checksum_value: Optional[str] = None,
    ):
        self.last_modified = datetime.now(tz=_gmt_zone_info)
        self.part_number = part_number
        self.size = size
        self.etag = etag
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value

    @property
    def quoted_etag(self) -> str:
        return f'"{self.etag}"'


class S3Multipart:
    parts: dict[PartNumber, S3Part]
    object: S3Object
    upload_id: MultipartUploadId
    checksum_value: Optional[str]
    initiated: datetime

    def __init__(
        self,
        key: ObjectKey,
        storage_class: StorageClass | ObjectStorageClass = StorageClass.STANDARD,
        expires: Optional[datetime] = None,
        expiration: Optional[datetime] = None,  # come from lifecycle
        checksum_algorithm: Optional[ChecksumAlgorithm] = None,
        encryption: Optional[ServerSideEncryption] = None,  # inherit bucket
        kms_key_id: Optional[SSEKMSKeyId] = None,  # inherit bucket
        bucket_key_enabled: bool = False,  # inherit bucket
        lock_mode: Optional[ObjectLockMode] = None,
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,
        lock_until: Optional[datetime] = None,
        website_redirect_location: Optional[WebsiteRedirectLocation] = None,
        acl: Optional[AccessControlPolicy] = None,  # TODO
        user_metadata: Optional[Metadata] = None,
        system_metadata: Optional[Metadata] = None,
        initiator: Optional[Owner] = None,
        tagging: Optional[dict[str, str]] = None,
        owner: Optional[Owner] = None,
    ):
        self.id = token_urlsafe(96)  # MultipartUploadId is 128 characters long
        self.initiated = datetime.now(tz=_gmt_zone_info)
        self.parts = {}
        self.initiator = initiator
        self.tagging = tagging
        self.checksum_value = None
        self.object = S3Object(
            key=key,
            user_metadata=user_metadata,
            system_metadata=system_metadata,
            storage_class=storage_class or StorageClass.STANDARD,
            expires=expires,
            expiration=expiration,
            checksum_algorithm=checksum_algorithm,
            encryption=encryption,
            kms_key_id=kms_key_id,
            bucket_key_enabled=bucket_key_enabled,
            lock_mode=lock_mode,
            lock_legal_status=lock_legal_status,
            lock_until=lock_until,
            website_redirect_location=website_redirect_location,
            acl=acl,
            owner=owner,
        )

    def complete_multipart(self, parts: CompletedPartList):
        last_part_index = len(parts) - 1
        # TODO: this part is currently not implemented, time permitting
        # if self.object.checksum_algorithm:
        #     checksum_key = f"Checksum{self.object.checksum_algorithm.upper()}"
        object_etag = hashlib.md5(usedforsecurity=False)
        pos = 0
        for index, part in enumerate(parts):
            part_number = part["PartNumber"]
            part_etag = part["ETag"].strip('"')

            s3_part = self.parts.get(part_number)
            if not s3_part or s3_part.etag != part_etag:
                raise InvalidPart(
                    "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
                    ETag=part_etag,
                    PartNumber=part_number,
                    UploadId=self.id,
                )

            # TODO: this part is currently not implemented, time permitting
            # part_checksum = part.get(checksum_key) if self.object.checksum_algorithm else None
            # if part_checksum and part_checksum != s3_part.checksum_value:
            #     raise Exception()

            if index != last_part_index and s3_part.size < S3_UPLOAD_PART_MIN_SIZE:
                raise EntityTooSmall(
                    "Your proposed upload is smaller than the minimum allowed size",
                    ETag=part_etag,
                    PartNumber=part_number,
                    MinSizeAllowed=S3_UPLOAD_PART_MIN_SIZE,
                    ProposedSize=s3_part.size,
                )

            object_etag.update(bytes.fromhex(s3_part.etag))
            # keep track of the parts size, as it can be queried afterward on the object as a Range
            self.object.parts[part_number] = (pos, s3_part.size)
            pos += s3_part.size

            multipart_etag = f"{object_etag.hexdigest()}-{len(parts)}"
            self.object.etag = multipart_etag


# TODO: use SynchronizedDefaultDict to prevent updates during iteration?
class KeyStore:
    """
    Object representing an S3 Un-versioned Bucket's Key Store. An object is mapped by a key, and you can simply
    retrieve the object from that key.
    """

    def __init__(self):
        self._store = {}

    def get(self, object_key: ObjectKey) -> S3Object | None:
        return self._store.get(object_key)

    def set(self, object_key: ObjectKey, s3_object: S3Object):
        self._store[object_key] = s3_object

    def pop(self, object_key: ObjectKey, default=None) -> S3Object | None:
        return self._store.pop(object_key, default)

    def values(self, *_, **__) -> list[S3Object | S3DeleteMarker]:
        return [value for value in self._store.values()]

    def is_empty(self) -> bool:
        return not self._store

    def __contains__(self, item):
        return item in self._store


class VersionedKeyStore:
    """
    Object representing an S3 Versioned Bucket's Key Store. An object is mapped by a key, and adding an object to the
    same key will create a new version of it. When deleting the object, a S3DeleteMarker is created and put on top
    of the version stack, to signal the object has been "deleted".
    This object allows easy retrieval and saving of new object versions.
    See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html
    """

    def __init__(self):
        self._store = defaultdict(dict)

    @classmethod
    def from_key_store(cls, keystore: KeyStore) -> "VersionedKeyStore":
        new_versioned_keystore = cls()
        for s3_object in keystore.values():
            # TODO: maybe do the object mutation inside the provider instead? but would need to iterate twice
            #  or do this whole operation inside the provider instead, when actually working on versioning
            s3_object.version_id = "null"
            new_versioned_keystore.set(object_key=s3_object.key, s3_object=s3_object)

        return new_versioned_keystore

    def get(
        self, object_key: ObjectKey, version_id: ObjectVersionId = None
    ) -> S3Object | S3DeleteMarker | None:
        """
        :param object_key: the key of the Object we need to retrieve
        :param version_id: Optional, if not specified, return the current version (last one inserted)
        :return: an S3Object or S3DeleteMarker
        """
        if not version_id and (versions := self._store.get(object_key)):
            for version_id in reversed(versions):
                return versions.get(version_id)

        return self._store.get(object_key, {}).get(version_id)

    def set(self, object_key: ObjectKey, s3_object: S3Object | S3DeleteMarker):
        """
        Set an S3 object, using its already set VersionId.
        If the bucket versioning is `Enabled`, then we're just inserting a new Version.
        If the bucket versioning is `Suspended`, the current object version will be set to `null`, so if setting a new
        object at the same key, we will override it at the `null` versionId entry.
        :param object_key: the key of the Object we are setting
        :param s3_object: the S3 object or S3DeleteMarker to set
        :return: None
        """
        existing_s3_object = self.get(object_key)
        if existing_s3_object:
            existing_s3_object.is_current = False

        self._store[object_key][s3_object.version_id] = s3_object

    def pop(
        self, object_key: ObjectKey, version_id: ObjectVersionId = None, default=None
    ) -> S3Object | S3DeleteMarker | None:
        versions = self._store.get(object_key)
        if not versions:
            return None

        object_version = versions.pop(version_id, default)
        if not versions:
            self._store.pop(object_key)
        else:
            existing_s3_object = self.get(object_key)
            existing_s3_object.is_current = True

        return object_version

    def values(self, with_versions: bool = False) -> list[S3Object | S3DeleteMarker]:
        if with_versions:
            return [
                object_version
                for values in self._store.values()
                for object_version in values.values()
            ]

        # if `with_versions` is False, then we need to return only the current version if it's not a DeleteMarker
        objects = []
        for object_key, versions in self._store.items():
            # we're getting the last set object in the versions dictionary
            for version_id in reversed(versions):
                current_object = versions[version_id]
                if isinstance(current_object, S3DeleteMarker):
                    break

                objects.append(versions[version_id])
                break

        return objects

    def is_empty(self) -> bool:
        return not self._store

    def __contains__(self, item):
        return item in self._store


class S3Store(BaseStore):
    buckets: dict[BucketName, S3Bucket] = CrossRegionAttribute(default=dict)
    global_bucket_map: dict[BucketName, AccountId] = CrossAccountAttribute(default=dict)
    aws_managed_kms_key_id: SSEKMSKeyId = LocalAttribute(default=str)

    # static tagging service instance
    TAGS: TaggingService = CrossAccountAttribute(default=TaggingService)


class BucketCorsIndex:
    def __init__(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @property
    def cors(self) -> dict[str, CORSConfiguration]:
        if self._cors_index_cache is None:
            self._bucket_index_cache, self._cors_index_cache = self._build_index()
        return self._cors_index_cache

    @property
    def buckets(self) -> set[str]:
        if self._bucket_index_cache is None:
            self._bucket_index_cache, self._cors_index_cache = self._build_index()
        return self._bucket_index_cache

    def invalidate(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @staticmethod
    def _build_index() -> tuple[set[BucketName], dict[BucketName, CORSConfiguration]]:
        buckets = set()
        cors_index = {}
        for account_id, regions in s3_stores.items():
            for bucket_name, bucket in regions[config.DEFAULT_REGION].buckets.items():
                bucket: S3Bucket
                buckets.add(bucket_name)
                if bucket.cors_rules is not None:
                    cors_index[bucket_name] = bucket.cors_rules

        return buckets, cors_index


class EncryptionParameters(NamedTuple):
    encryption: ServerSideEncryption
    kms_key_id: SSEKMSKeyId
    bucket_key_enabled: BucketKeyEnabled


class ObjectLockParameters(NamedTuple):
    lock_until: ObjectLockRetainUntilDate
    lock_legal_status: ObjectLockLegalHoldStatus
    lock_mode: ObjectLockMode | ObjectLockRetentionMode


s3_stores = AccountRegionBundle[S3Store]("s3", S3Store)
