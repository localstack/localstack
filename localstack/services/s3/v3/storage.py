import abc
import base64
import hashlib
from collections import defaultdict
from io import BytesIO, RawIOBase
from shutil import rmtree
from tempfile import SpooledTemporaryFile, mkdtemp
from threading import RLock
from typing import IO, Iterable, Iterator, Optional, TypedDict

from readerwriterlock import rwlock

from localstack.aws.api.s3 import BucketName, MultipartUploadId, PartNumber
from localstack.services.s3.constants import S3_CHUNK_SIZE
from localstack.services.s3.utils import ChecksumHash, ParsedRange, get_s3_checksum
from localstack.services.s3.v3.models import S3Multipart, S3Object, S3Part

# max file size for S3 objects kept in memory (500 KB by default)
# TODO: make it configurable
S3_MAX_FILE_SIZE_BYTES = 512 * 1024


class LockedFileMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # this lock allows us to make `seek` and `read` operation as an atomic one, without an external reader
        # modifying the internal position of the stream
        self.position_lock = RLock()
        # these locks are for the read/write lock issues. No writer should modify the object while a reader is
        # currently iterating over it.
        # see:
        self.readwrite_lock = rwlock.RWLockWrite()


class LockedSpooledTemporaryFile(LockedFileMixin, SpooledTemporaryFile):
    def seekable(self) -> bool:
        return True


class LimitedIterableStream(Iterable[bytes]):
    def __init__(self, iterable: Iterable[bytes], max_length: int):
        self.iterable = iterable
        self.max_length = max_length

    def __iter__(self):
        for chunk in self.iterable:
            read = len(chunk)
            if self.max_length - read >= 0:
                self.max_length -= read
                yield chunk
            else:
                yield chunk[: self.max_length + 1]
                break

        return


class LimitedStream(RawIOBase):
    """
    This utility class allows to return a range from the underlying stream representing an S3 Object.
    """

    def __init__(self, base_stream: IO[bytes] | "S3StoredObject", range_data: ParsedRange):
        super().__init__()
        self._base_stream = base_stream
        self._pos = range_data.begin
        self._max_length = range_data.content_length

    def read(self, s: int = -1) -> bytes | None:
        if s is None or s < 0:
            amount = self._max_length
        else:
            amount = min(self._max_length, s)

        self._base_stream.seek(self._pos)
        data = self._base_stream.read(amount)

        if not data:
            return b""
        read_amount = len(data)
        self._max_length -= read_amount
        self._pos += read_amount

        return data


# TODO: naming? Shared between Object and Part
class S3StoredObject(abc.ABC, Iterable[bytes]):
    s3_object: S3Object

    def __init__(self, s3_object: S3Object | S3Part):
        self.s3_object = s3_object

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractmethod
    def write(self, s: IO[bytes] | "S3StoredObject") -> int:
        pass

    @abc.abstractmethod
    def append(self, part: "S3StoredObject") -> int:
        pass

    @abc.abstractmethod
    def read(self, s: int = -1) -> bytes | None:
        pass

    @abc.abstractmethod
    def seek(self, offset: int, whence: int = 0) -> int:
        pass

    @abc.abstractmethod
    def checksum(self) -> Optional[str]:
        if not self.s3_object.checksum_algorithm:
            return None

    @abc.abstractmethod
    def __iter__(self) -> Iterator[bytes]:
        pass


class S3StoredMultipart(abc.ABC):
    parts: dict[PartNumber, S3StoredObject]
    s3_multipart: S3Multipart
    _s3_store: "S3ObjectStore"

    def __init__(self, s3_store: "S3ObjectStore", bucket: BucketName, s3_multipart: S3Multipart):
        self.s3_multipart = s3_multipart
        self.bucket = bucket
        self._s3_store = s3_store
        self.parts = {}

    @abc.abstractmethod
    def open(self, s3_part: S3Part) -> S3StoredObject:
        pass

    @abc.abstractmethod
    def remove_part(self, s3_part: S3Part):
        pass

    @abc.abstractmethod
    def complete_multipart(self, parts: list[PartNumber]) -> S3StoredObject:
        pass

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractmethod
    def copy_from_object(
        self,
        s3_part: S3Part,
        src_bucket: BucketName,
        src_s3_object: S3Object,
        range_data: ParsedRange,
    ) -> S3StoredObject:
        pass


class S3ObjectStore(abc.ABC):
    @abc.abstractmethod
    def open(self, bucket: BucketName, s3_object: S3Object) -> S3StoredObject:
        pass

    @abc.abstractmethod
    def remove(self, bucket: BucketName, s3_object: S3Object):
        pass

    @abc.abstractmethod
    def copy(
        self,
        src_bucket: BucketName,
        src_object: S3Object,
        dest_bucket: BucketName,
        dest_object: S3Object,
    ) -> S3StoredObject:
        pass

    @abc.abstractmethod
    def get_multipart(self, bucket: BucketName, upload_id: MultipartUploadId) -> S3StoredMultipart:
        pass

    @abc.abstractmethod
    def remove_multipart(self, bucket: BucketName, s3_multipart: S3Multipart):
        pass

    @abc.abstractmethod
    def close(self):
        pass


class EphemeralS3StoredObject(S3StoredObject):
    file: LockedSpooledTemporaryFile
    size: int
    _pos: int
    etag: Optional[str]
    checksum_hash: Optional[ChecksumHash]
    _checksum: Optional[str]

    def __init__(self, s3_object: S3Object | S3Part, file: LockedSpooledTemporaryFile):
        super().__init__(s3_object=s3_object)
        self.file = file
        self.size = 0
        self.etag = None
        self.checksum_hash = None
        self._checksum = None
        self._pos = 0

    def read(self, s: int = -1) -> bytes | None:
        with self.file.position_lock:
            self.file.seek(self._pos)
            data = self.file.read(s)
        if not data:
            return b""

        read = len(data)
        self._pos += read
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        with self.file.position_lock:
            self.file.seek(offset, whence)
            self._pos = self.file.tell()

        return self._pos

    def write(self, stream: IO[bytes] | "EphemeralS3StoredObject" | LimitedStream) -> int:
        if stream is None:
            stream = BytesIO()

        if self.s3_object.checksum_algorithm:
            self.checksum_hash = get_s3_checksum(self.s3_object.checksum_algorithm)

        file = self.file
        with file.readwrite_lock.gen_wlock():
            file.seek(0)
            file.truncate()

            etag = hashlib.md5(usedforsecurity=False)

            while data := stream.read(S3_CHUNK_SIZE):
                file.write(data)
                etag.update(data)
                if self.checksum_hash:
                    self.checksum_hash.update(data)

            etag = etag.hexdigest()
            self.size = self.s3_object.size = file.tell()
            self.etag = self.s3_object.etag = etag

            file.seek(0)
            self._pos = 0

            return self.size

    def append(self, part: IO[bytes] | "EphemeralS3StoredObject") -> int:
        read = 0
        while data := part.read(S3_CHUNK_SIZE):
            self.file.write(data)
            read += len(data)

        return read

    def close(self):
        return self.file.close()

    def checksum(self) -> Optional[str]:
        if not self.s3_object.checksum_algorithm:
            return
        if not self.checksum_hash:
            # we didn't write or yet calculated the checksum, so calculate with what is in the underlying file
            self.checksum_hash = get_s3_checksum(self.s3_object.checksum_algorithm)
            original_pos = self._pos
            self._pos = 0
            while data := self.read(S3_CHUNK_SIZE):
                self.checksum_hash.update(data)

            self._pos = original_pos

        if not self._checksum:
            self._checksum = base64.b64encode(self.checksum_hash.digest()).decode()

        return self._checksum

    def __iter__(self) -> Iterator[bytes]:
        with self.file.readwrite_lock.gen_rlock():
            while data := self.read(S3_CHUNK_SIZE):
                if not data:
                    return b""

                yield data


class EphemeralS3StoredMultipart(S3StoredMultipart):
    upload_dir: str
    _s3_store: "EphemeralS3ObjectStore"
    parts: dict[PartNumber, EphemeralS3StoredObject]

    def __init__(
        self,
        s3_store: "EphemeralS3ObjectStore",
        bucket: BucketName,
        s3_multipart: S3Multipart,
        upload_dir: str,
    ):
        super().__init__(s3_store=s3_store, bucket=bucket, s3_multipart=s3_multipart)
        self.upload_dir = upload_dir

    def open(self, s3_part: S3Part) -> EphemeralS3StoredObject:
        if not (stored_part := self.parts.get(s3_part.part_number)):
            file = LockedSpooledTemporaryFile(dir=self.upload_dir, max_size=S3_MAX_FILE_SIZE_BYTES)
            stored_part = EphemeralS3StoredObject(s3_part, file)
            self.parts[s3_part.part_number] = stored_part

        return stored_part

    def remove_part(self, s3_part: S3Part):
        stored_part = self.parts.pop(s3_part.part_number, None)
        if stored_part:
            stored_part.close()

    def complete_multipart(self, parts: list[PartNumber]) -> EphemeralS3StoredObject:
        s3_stored_object = self._s3_store.open(self.bucket, self.s3_multipart.object)
        for part_number in parts:
            stored_part = self.parts.get(part_number)
            s3_stored_object.append(stored_part)

        return s3_stored_object

    def close(self):
        for part in self.parts.values():
            part.close()

        self.parts.clear()

    def copy_from_object(
        self,
        s3_part: S3Part,
        src_bucket: BucketName,
        src_s3_object: S3Object,
        range_data: ParsedRange,
    ) -> EphemeralS3StoredObject:
        src_stored_object = self._s3_store.open(src_bucket, src_s3_object)
        stored_part = self.open(s3_part)

        object_slice = LimitedStream(src_stored_object, range_data=range_data)
        stored_part.write(object_slice)
        return stored_part

    def _get_part(self, s3_part: S3Part) -> EphemeralS3StoredObject:
        if not (stored_part := self.parts.get(s3_part.part_number)):
            file = LockedSpooledTemporaryFile(dir=self.upload_dir, max_size=S3_MAX_FILE_SIZE_BYTES)
            stored_part = EphemeralS3StoredObject(s3_part, file)
            self.parts[s3_part.part_number] = stored_part

        return stored_part


class BucketTemporaryFileSystem(TypedDict):
    keys: dict[str, LockedSpooledTemporaryFile]
    multiparts: dict[MultipartUploadId, EphemeralS3StoredMultipart]


class EphemeralS3ObjectStore(S3ObjectStore):
    """
    This simulates a filesystem where S3 will store its assets
    The structure is the following:
    <bucket-name-1>/
    keys/
    ├─ <hash-key-1> -> fileobj
    ├─ <hash-key-2> -> fileobj
    multiparts/
    ├─ <upload-id-1>/
    │  ├─ <part-number-1> -> fileobj
    │  ├─ <part-number-2> -> fileobj
    """

    def __init__(self):
        self._filesystem: dict[BucketName, BucketTemporaryFileSystem] = defaultdict(
            lambda: {"keys": {}, "multiparts": {}}
        )
        # this allows us to map bucket names to temporary directory name, to not have a flat structure inside the
        # temporary directory used by SpooledTemporaryFile
        self._directory_mapping: dict[str, str] = {}

    def open(self, bucket: BucketName, s3_object: S3Object) -> EphemeralS3StoredObject:
        key = self._key_from_s3_object(s3_object)
        if not (file := self._get_object_file(bucket, key)):
            if not (bucket_tmp_dir := self._directory_mapping.get(bucket)):
                bucket_tmp_dir = self._create_bucket_directory(bucket)

            file = LockedSpooledTemporaryFile(dir=bucket_tmp_dir, max_size=S3_MAX_FILE_SIZE_BYTES)
            self._filesystem[bucket]["keys"][key] = file

        return EphemeralS3StoredObject(s3_object=s3_object, file=file)

    def remove(self, bucket: BucketName, s3_object: S3Object):
        if keys := self._filesystem.get(bucket, {}).get("keys", {}):
            key = self._key_from_s3_object(s3_object)
            keys.pop(key, None)

        # if the bucket is now empty after removing, we can delete the directory
        if not keys and not self._filesystem.get(bucket, {}).get("multiparts"):
            self._delete_bucket_directory(bucket)

    def copy(
        self,
        src_bucket: BucketName,
        src_object: S3Object,
        dest_bucket: BucketName,
        dest_object: S3Object,
    ) -> EphemeralS3StoredObject:
        if src_bucket == dest_bucket and src_object.key == dest_object.key:
            return self.open(src_bucket, src_object)

        src_stored_object = self.open(src_bucket, src_object)
        dest_stored_object = self.open(dest_bucket, dest_object)

        dest_stored_object.write(src_stored_object)

        return dest_stored_object

    def get_multipart(
        self, bucket: BucketName, s3_multipart: S3Multipart
    ) -> EphemeralS3StoredMultipart:
        upload_key = self._resolve_upload_directory(bucket, s3_multipart.id)
        if not (multipart := self._get_multipart(bucket, upload_key)):

            upload_dir = self._create_upload_directory(bucket, s3_multipart.id)

            multipart = EphemeralS3StoredMultipart(self, s3_multipart, upload_dir)
            self._filesystem[bucket]["multiparts"][upload_key] = multipart

        return multipart

    def remove_multipart(self, bucket: BucketName, s3_multipart: S3Multipart):
        if multiparts := self._filesystem.get(bucket, {}).get("multiparts", {}):
            upload_key = self._resolve_upload_directory(bucket, s3_multipart.id)
            if multipart := multiparts.pop(upload_key, None):
                multipart.close()

        # if the bucket is now empty after removing, we can delete the directory
        if not multiparts and not self._filesystem.get(bucket, {}).get("keys"):
            self._delete_bucket_directory(bucket)

    def close(self):
        for bucket in self._filesystem.values():
            if keys := bucket.get("keys"):
                for file in keys.values():
                    file.close()
                keys.clear()

            if multiparts := bucket.get("multiparts"):
                for multipart in multiparts.values():
                    multipart.close()
                multiparts.clear()

    @staticmethod
    def _key_from_s3_object(s3_object: S3Object) -> str:
        return str(hash(f"{s3_object.key}?{s3_object.version_id or 'null'}"))

    def _get_object_file(self, bucket: BucketName, key: str) -> LockedSpooledTemporaryFile | None:
        return self._filesystem.get(bucket, {}).get("keys", {}).get(key)

    def _get_multipart(self, bucket: BucketName, upload_key: str) -> S3StoredMultipart | None:
        return self._filesystem.get(bucket, {}).get("multiparts", {}).get(upload_key)

    @staticmethod
    def _resolve_upload_directory(bucket_name: BucketName, upload_id: MultipartUploadId) -> str:
        return f"{bucket_name}/{upload_id}"

    def _create_bucket_directory(self, bucket_name: BucketName) -> str:
        """
        Create a temporary directory representing a bucket
        :param bucket_name
        """
        tmp_dir = mkdtemp()
        self._directory_mapping[bucket_name] = tmp_dir
        return tmp_dir

    def _delete_bucket_directory(self, bucket_name: BucketName):
        """
        Delete the temporary directory representing a bucket
        :param bucket_name
        """
        tmp_dir = self._directory_mapping.get(bucket_name)
        if tmp_dir:
            rmtree(tmp_dir, ignore_errors=True)

    def _create_upload_directory(
        self, bucket_name: BucketName, upload_id: MultipartUploadId
    ) -> str:
        """
        Create a temporary
        :param bucket_name:
        :param upload_id:
        :return:
        """
        bucket_tmp_dir = self._directory_mapping.get(bucket_name)
        if not bucket_tmp_dir:
            self._create_bucket_directory(bucket_name)
            bucket_tmp_dir = self._directory_mapping.get(bucket_name)

        upload_tmp_dir = mkdtemp(dir=bucket_tmp_dir)
        self._directory_mapping[f"{bucket_name}/{upload_id}"] = upload_tmp_dir
        return upload_tmp_dir

    def _delete_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        tmp_dir = self._directory_mapping.get(f"{bucket_name}/{upload_id}")
        if tmp_dir:
            rmtree(tmp_dir, ignore_errors=True)
