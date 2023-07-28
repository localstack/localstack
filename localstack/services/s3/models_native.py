import logging
from collections import defaultdict
from datetime import datetime
from io import RawIOBase
from typing import IO, Any, Literal, Optional, Union

from werkzeug.datastructures.headers import Headers

from localstack import config
from localstack.aws.api.s3 import (
    AccountId,
    AnalyticsConfiguration,
    AnalyticsId,
    BucketAccelerateStatus,
    BucketName,
    BucketRegion,
    ChecksumAlgorithm,
    CORSConfiguration,
    ETag,
    Expiration,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InvalidArgument,
    LifecycleRules,
    LoggingEnabled,
    Metadata,
    MethodNotAllowed,
    MultipartUploadId,
    NoSuchKey,
    NoSuchVersion,
    NotificationConfiguration,
    ObjectKey,
    ObjectLockConfiguration,
    ObjectLockLegalHoldStatus,
    ObjectLockMode,
    ObjectOwnership,
    ObjectStorageClass,
    ObjectVersionId,
    Owner,
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
from localstack.services.s3.storage import LockedSpooledTemporaryFile
from localstack.services.s3.utils import (
    ParsedRange,
    get_owner_for_account_id,
    iso_8601_datetime_without_milliseconds_s3,
    rfc_1123_datetime,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    CrossRegionAttribute,
)

# TODO: beware of timestamp data, we need the snapshot to be more precise for S3, with the different types
# moto had a lot of issue with it? not sure about our parser/serializer

LOG = logging.getLogger(__name__)


# note: not really a need to use a dataclass here, as it has a lot of fields, but only a few are set at creation
class S3Bucket:
    name: BucketName
    bucket_account_id: AccountId
    bucket_region: BucketRegion
    creation_date: datetime
    multiparts: dict[MultipartUploadId, Any]  # TODO
    objects: Union["KeyStore", "VersionedKeyStore"]
    versioning_status: Literal[None, "Enabled", "Disabled"]
    lifecycle_rules: LifecycleRules
    policy: Optional[Policy]
    website_configuration: WebsiteConfiguration
    acl: str  # TODO: change this
    cors_rules: CORSConfiguration
    logging: LoggingEnabled
    notification_configuration: NotificationConfiguration
    payer: Payer
    encryption_rule: Optional[
        ServerSideEncryptionRule
    ]  # TODO validate if there can be more than one rule
    public_access_block: PublicAccessBlockConfiguration
    accelerate_status: BucketAccelerateStatus
    object_ownership: ObjectOwnership
    object_lock_configuration: Optional[ObjectLockConfiguration]
    object_lock_enabled: bool
    intelligent_tiering_configuration: dict[IntelligentTieringId, IntelligentTieringConfiguration]
    analytics_configuration: dict[AnalyticsId, AnalyticsConfiguration]
    replication: ReplicationConfiguration
    owner: Owner

    # set all buckets parameters here
    def __init__(
        self,
        name: BucketName,
        account_id: AccountId,
        bucket_region: BucketRegion,
        acl=None,  # TODO: validate ACL first, create utils for validating and consolidating
        object_ownership: ObjectOwnership = None,
        object_lock_enabled_for_bucket: bool = None,
    ):
        self.name = name
        self.bucket_account_id = account_id
        self.bucket_region = bucket_region
        self.objects = KeyStore()
        self.object_ownership = object_ownership
        self.object_lock_enabled = object_lock_enabled_for_bucket
        self.encryption_rule = None  # TODO
        self.creation_date = datetime.utcnow()
        self.multiparts = {}
        self.versioning_status = None

        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html
        self.owner = get_owner_for_account_id(account_id)

    def get_object(
        self,
        key: ObjectKey,
        version_id: ObjectVersionId = None,
        http_method: Literal["GET", "PUT", "HEAD"] = "GET",  # TODO: better?
    ) -> "S3Object":
        """
        :param key: the Object Key
        :param version_id: optional, the versionId of the object
        :param http_method: the HTTP method of the original call. This is necessary for the exception if the bucket is
        versioned or suspended
        see: https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html
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
                elif isinstance(s3_object_version, S3DeleteMarker):
                    raise MethodNotAllowed(
                        "The specified method is not allowed against this resource.",
                        Method=http_method,
                        ResourceType="DeleteMarker",
                        DeleteMarker=True,
                        Allow="delete",
                    )
                return s3_object_version

            s3_object = self.objects.get(key)

            if not s3_object:
                raise NoSuchKey("The specified key does not exist.", Key=key)

            elif isinstance(s3_object, S3DeleteMarker):
                raise NoSuchKey(
                    "The specified key does not exist.",
                    Key=key,
                    DeleteMarker=True,
                )

        return s3_object


# note: might be migrated to dataclass once the full API is set
class S3Object:
    key: ObjectKey
    version_id: Optional[ObjectVersionId]
    size: Size
    etag: ETag
    user_metadata: Metadata
    system_metadata: Metadata
    last_modified: datetime
    expires: Optional[datetime]
    expiration: Optional[Expiration]  # come from lifecycle
    storage_class: StorageClass | ObjectStorageClass
    encryption: Optional[ServerSideEncryption]  # inherit bucket
    kms_key_id: Optional[SSEKMSKeyId]  # inherit bucket
    bucket_key_enabled: Optional[bool]  # inherit bucket
    checksum_algorithm: ChecksumAlgorithm
    checksum_value: str
    lock_mode: Optional[ObjectLockMode]
    lock_legal_status: Optional[ObjectLockLegalHoldStatus]
    lock_until: Optional[datetime]
    website_redirect_location: Optional[WebsiteRedirectLocation]
    acl: Optional[str]  # TODO: we need to change something here, how it's done?
    is_current: bool
    parts: Optional[list[tuple[int, int]]]
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
        lock_mode: Optional[ObjectLockMode] = None,
        lock_legal_status: Optional[ObjectLockLegalHoldStatus] = None,
        lock_until: Optional[datetime] = None,
        website_redirect_location: Optional[WebsiteRedirectLocation] = None,
        acl: Optional[str] = None,  # TODO
    ):
        self.key = key
        self.user_metadata = {k.lower(): v for k, v in user_metadata.items()}
        self.system_metadata = system_metadata
        self.version_id = version_id
        self.storage_class = storage_class or StorageClass.STANDARD
        self.etag = etag
        self.size = size
        self.expires = expires
        self.checksum_algorithm = checksum_algorithm
        self.checksum_value = checksum_value
        self.encryption = encryption
        # TODO: validate the format for kms_key_id, always store the ARN even if just the ID
        self.kms_key_id = kms_key_id
        self.bucket_key_enabled = bucket_key_enabled
        self.lock_mode = lock_mode
        self.lock_legal_status = lock_legal_status
        self.lock_until = lock_until
        self.acl = acl
        self.expiration = expiration
        self.website_redirect_location = website_redirect_location
        self.is_current = True
        self.last_modified = datetime.utcnow()
        self.parts = []
        self.restore = None

    def get_system_metadata_fields(self):
        headers = Headers()
        headers["LastModified"] = self.last_modified_rfc1123
        headers["ContentLength"] = str(self.size)
        headers["ETag"] = self.quoted_etag
        if self.expires:
            headers["Expires"] = self.expires_rfc1123

        for metadata_key, metadata_value in self.system_metadata.items():
            headers[metadata_key] = metadata_value

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


class S3DeleteMarker:
    key: ObjectKey
    version_id: str
    last_modified: datetime
    is_current: bool

    def __init__(self, key: ObjectKey, version_id: ObjectVersionId):
        self.key = key
        self.version_id = version_id
        self.last_modified = datetime.utcnow()
        self.is_current = True


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
        self._store[object_key][s3_object.version_id] = S3Object

    def pop(
        self, object_key: ObjectKey, version_id: ObjectVersionId = None, default=None
    ) -> S3Object | S3DeleteMarker | None:
        versions = self._store.get(object_key)
        if not versions:
            return None

        object_version = versions.pop(version_id, default)
        if not versions:
            self._store.pop(object_key)

        return object_version

    def values(self, with_versions: bool = False) -> list[S3Object | S3DeleteMarker]:
        if with_versions:
            return [object_version for values in self._store.values() for object_version in values]

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


class S3StoreV2(BaseStore):
    buckets: dict[BucketName, S3Bucket] = CrossRegionAttribute(default=dict)
    global_bucket_map: dict[BucketName, AccountId] = CrossAccountAttribute(default=dict)


class BucketCorsIndexV2:
    def __init__(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @property
    def cors(self) -> dict[str, CORSConfiguration]:
        if self._cors_index_cache is None:
            self._cors_index_cache = self._build_index()
        return self._cors_index_cache

    @property
    def buckets(self) -> set[str]:
        if self._bucket_index_cache is None:
            self._bucket_index_cache = self._build_index()
        return self._bucket_index_cache

    def invalidate(self):
        self._cors_index_cache = None
        self._bucket_index_cache = None

    @staticmethod
    def _build_index() -> tuple[set[BucketName], dict[BucketName, CORSConfiguration]]:
        buckets = set()
        cors_index = {}
        for account_id, regions in s3_stores_v2.items():
            for bucket_name, bucket in regions[config.DEFAULT_REGION].buckets.items():
                bucket: S3Bucket
                buckets.add(bucket_name)
                if bucket.cors_rules is not None:
                    cors_index[bucket_name] = bucket.cors_rules

        return buckets, cors_index


class PartialStream(RawIOBase):
    """
    This utility class allows to return a range from the underlying stream representing an S3 Object.
    """

    def __init__(
        self, base_stream: IO[bytes] | LockedSpooledTemporaryFile, range_data: ParsedRange
    ):
        super().__init__()
        self._base_stream = base_stream
        self._pos = range_data.begin
        self._max_length = range_data.content_length

    def read(self, s: int = -1) -> bytes | None:
        if s is None or s < 0:
            amount = self._max_length
        else:
            amount = min(self._max_length, s)

        with self._base_stream.position_lock:
            self._base_stream.seek(self._pos)
            data = self._base_stream.read(amount)

        if not data:
            return b""
        read_amount = len(data)
        self._max_length -= read_amount
        self._pos += read_amount

        return data

    def readable(self) -> bool:
        return True


s3_stores_v2 = AccountRegionBundle[S3StoreV2]("s3", S3StoreV2)
