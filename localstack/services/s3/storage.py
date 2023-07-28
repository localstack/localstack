import abc
from collections import defaultdict
from shutil import rmtree
from tempfile import SpooledTemporaryFile, mkdtemp
from threading import RLock
from typing import Iterator, TypedDict

from readerwriterlock import rwlock

from localstack.aws.api.s3 import (
    BucketName,
    MultipartUploadId,
    ObjectKey,
    ObjectVersionId,
    PartNumber,
)
from localstack.services.s3.constants import S3_CHUNK_SIZE

# max file size for S3 objects kept in memory (500 KB by default)
# TODO: make it configurable
S3_MAX_FILE_SIZE_BYTES = 512 * 1024


class BaseStorageBackend(abc.ABC):
    """
    Base class abstraction for S3 Storage Backend. This allows decoupling between S3 metadata and S3 file objects
    """

    def create_bucket_directory(self, bucket_name: BucketName):
        raise NotImplementedError

    def delete_bucket_directory(self, bucket_name: BucketName):
        raise NotImplementedError

    def create_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        raise NotImplementedError

    def delete_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        raise NotImplementedError

    def get_key_fileobj(
        self, bucket_name: BucketName, object_key: ObjectKey, version_id: ObjectVersionId = None
    ):
        raise NotImplementedError

    def delete_key_fileobj(
        self, bucket_name: BucketName, object_key: ObjectKey, version_id: str = None
    ):
        raise NotImplementedError

    def get_part_fileobj(
        self, bucket_name: BucketName, upload_id: MultipartUploadId, part_number: PartNumber
    ):
        raise NotImplementedError

    def delete_part_fileobj(
        self, bucket_name: BucketName, upload_id: MultipartUploadId, part_number: PartNumber
    ):
        raise NotImplementedError

    def get_list_parts_fileobjs(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        raise NotImplementedError

    def delete_multipart_fileobjs(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        raise NotImplementedError

    @staticmethod
    def _get_fileobj_key(object_key: ObjectKey, version_id: ObjectVersionId = None) -> str:
        return str(hash(f"{object_key}?{version_id}"))

    @staticmethod
    def _get_fileobj_part(multipart_id: MultipartUploadId) -> str:
        # TODO: might not need to hash it? just use the upload_id?
        return str(hash(multipart_id))


class BucketTemporaryFileSystem(TypedDict):
    keys: dict[str, "LockedSpooledTemporaryFile"]
    multiparts: dict[MultipartUploadId, dict[PartNumber, "LockedSpooledTemporaryFile"]]


class TemporaryStorageBackend(BaseStorageBackend):
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
            self._get_bucket_filesystem
        )
        # this allows us to map bucket names to temporary directory name, to not have a flat structure inside the
        # temporary directory used by SpooledTemporaryFile
        self._directory_mapping: dict[str, str] = {}

    @staticmethod
    def _get_bucket_filesystem():
        return {"keys": {}, "multiparts": defaultdict(dict)}

    def create_bucket_directory(self, bucket_name: BucketName):
        """
        Create a temporary directory representing a bucket
        :param bucket_name
        """
        tmp_dir = mkdtemp()
        self._directory_mapping[bucket_name] = tmp_dir

    def delete_bucket_directory(self, bucket_name: BucketName):
        """
        Delete the temporary directory representing a bucket
        :param bucket_name
        """
        tmp_dir = self._directory_mapping.get(bucket_name)
        if tmp_dir:
            rmtree(tmp_dir, ignore_errors=True)

    def create_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        """
        Create a temporary
        :param bucket_name:
        :param upload_id:
        :return:
        """
        bucket_tmp_dir = self._directory_mapping.get(bucket_name)
        if not bucket_tmp_dir:
            self.create_bucket_directory(bucket_name)
            bucket_tmp_dir = self._directory_mapping.get(bucket_name)

        upload_tmp_dir = mkdtemp(dir=bucket_tmp_dir)
        self._directory_mapping[f"{bucket_name}/{upload_id}"] = upload_tmp_dir

    def delete_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        tmp_dir = self._directory_mapping.get(f"{bucket_name}/{upload_id}")
        if tmp_dir:
            rmtree(tmp_dir, ignore_errors=True)

    def get_key_fileobj(
        self, bucket_name: BucketName, object_key: ObjectKey, version_id: ObjectVersionId = None
    ) -> "LockedSpooledTemporaryFile":
        key = self._get_fileobj_key(object_key, version_id)
        if not (fileobj := self._filesystem.get(bucket_name, {}).get("keys", {}).get(key)):
            # if, for some race condition, bucket_tmp_dir is None, the SpooledFile will be in the default tmp dir
            # which is fine
            bucket_tmp_dir = self._directory_mapping.get(bucket_name)
            fileobj = LockedSpooledTemporaryFile(
                dir=bucket_tmp_dir, max_size=S3_MAX_FILE_SIZE_BYTES
            )
            self._filesystem[bucket_name]["keys"][key] = fileobj

        return fileobj

    def delete_key_fileobj(
        self, bucket_name: BucketName, object_key: ObjectKey, version_id: str = None
    ):
        key = self._get_fileobj_key(object_key, version_id)
        if fileobj := self._filesystem.get(bucket_name, {}).get("keys", {}).get(key):
            fileobj.close()

        self._filesystem.get(bucket_name, {}).get("keys", {}).pop(key, None)

    def get_part_fileobj(
        self, bucket_name: BucketName, upload_id: MultipartUploadId, part_number: PartNumber
    ) -> "LockedSpooledTemporaryFile":
        key = self._get_fileobj_part(upload_id)
        if not (
            fileobj := self._filesystem.get(bucket_name, {})
            .get("multiparts", {})
            .get(key, {})
            .get(part_number)
        ):
            upload_tmp_dir = self._directory_mapping.get(f"{bucket_name}/{upload_id}")
            fileobj = LockedSpooledTemporaryFile(
                dir=upload_tmp_dir, max_size=S3_MAX_FILE_SIZE_BYTES
            )
            self._filesystem[bucket_name]["multiparts"][key][part_number] = fileobj

        return fileobj

    def delete_part_fileobj(
        self, bucket_name: BucketName, upload_id: MultipartUploadId, part_number: PartNumber
    ):
        key = self._get_fileobj_part(upload_id)
        if (
            fileobj := self._filesystem.get(bucket_name, {})
            .get("multiparts", {})
            .get(key, {})
            .get(part_number)
        ):
            fileobj.close()

        self._filesystem.get(bucket_name, {}).get("multiparts", {}).get(key, {}).pop(
            part_number, None
        )

    def get_list_parts_fileobjs(
        self, bucket_name: BucketName, upload_id: MultipartUploadId
    ) -> list["LockedSpooledTemporaryFile"]:
        key = self._get_fileobj_part(upload_id)
        parts = self._filesystem.get(bucket_name, {}).get("multiparts", {}).get(key, {})
        return [fileobj for part_number, fileobj in sorted(parts.items())]

    def delete_multipart_fileobjs(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        key = self._get_fileobj_part(upload_id)
        parts = self._filesystem.get(bucket_name, {}).get("multiparts", {}).get(key, {})
        for fileobj in parts.values():
            fileobj.close()

        self._filesystem.get(bucket_name, {}).get("multiparts", {}).pop(key, None)


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

    def get_locked_stream_iterator(self) -> Iterator[bytes]:
        def stream_iterator() -> Iterator[bytes]:
            pos = 0
            with self.readwrite_lock.gen_rlock():
                while True:
                    # don't read more than the max content-length
                    with self.position_lock:
                        self.seek(pos)
                        data = self.read(S3_CHUNK_SIZE)
                    if not data:
                        return b""

                    read = len(data)
                    pos += read

                    yield data

        return stream_iterator()

    def get_locked_range_stream_iterator(self, max_length: int, begin: int) -> Iterator[bytes]:
        def stream_iterator() -> Iterator[bytes]:
            pos = begin
            _max_length = max_length
            with self.readwrite_lock.gen_rlock():
                while True:
                    # don't read more than the max content-length
                    amount = min(_max_length, S3_CHUNK_SIZE)
                    with self.position_lock:
                        self.seek(pos)
                        data = self.read(amount)
                    if not data:
                        return b""

                    read = len(data)
                    pos += read
                    _max_length -= read

                    yield data

        return stream_iterator()


class FilesystemStorageBackend(BaseStorageBackend):
    pass


class LockedSpooledFile:  # TODO: implement this for persistence
    pass
