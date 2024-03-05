import base64
import hashlib
import os
import threading
import time
from collections import defaultdict
from io import BytesIO, UnsupportedOperation
from shutil import rmtree
from tempfile import SpooledTemporaryFile, mkdtemp
from threading import RLock
from typing import IO, Iterator, Literal, Optional, TypedDict

from readerwriterlock import rwlock

from localstack.aws.api.s3 import BucketName, MultipartUploadId, PartNumber
from localstack.services.s3.constants import S3_CHUNK_SIZE
from localstack.services.s3.utils import ChecksumHash, ObjectRange, get_s3_checksum
from localstack.services.s3.v3.models import S3Multipart, S3Object, S3Part
from localstack.utils.files import mkdir

from .core import LimitedStream, S3ObjectStore, S3StoredMultipart, S3StoredObject

# max file size for S3 objects kept in memory (500 KB by default)
# TODO: make it configurable
S3_MAX_FILE_SIZE_BYTES = 512 * 1024


class LockedFileMixin:
    """Mixin with 2 locks: one lock used to lock an underlying stream position between seek and read, and a readwrite"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # this lock allows us to make `seek` and `read` operation as an atomic one, without an external reader
        # modifying the internal position of the stream
        self.position_lock = RLock()
        # these locks are for the read/write lock issues. No writer should modify the object while a reader is
        # currently iterating over it.
        # see:
        self.readwrite_lock = rwlock.RWLockWrite()
        self.internal_last_modified = 0


class LockedSpooledTemporaryFile(LockedFileMixin, SpooledTemporaryFile):
    """Creates a SpooledTemporaryFile with locks"""

    def seekable(self) -> bool:
        return True


class EphemeralS3StoredObject(S3StoredObject):
    """
    An Ephemeral S3StoredObject, using LockedSpooledTemporaryFile as its underlying file object.
    """

    file: LockedSpooledTemporaryFile
    size: int
    _pos: int
    etag: Optional[str]
    checksum_hash: Optional[ChecksumHash]
    _checksum: Optional[str]
    _lock: rwlock.Lockable

    def __init__(
        self,
        s3_object: S3Object | S3Part,
        file: LockedSpooledTemporaryFile,
        mode: Literal["r", "w"] = "r",
    ):
        super().__init__(s3_object=s3_object, mode=mode)
        self.file = file
        self.size = 0
        self._etag = None
        self.checksum_hash = None
        self._checksum = None
        self._pos = 0
        self._lock = (
            self.file.readwrite_lock.gen_wlock()
            if mode == "w"
            else self.file.readwrite_lock.gen_rlock()
        )
        self._lock.acquire()

    def read(self, s: int = -1) -> bytes | None:
        """Read at most `s` bytes from the underlying fileobject, and keeps the internal position"""
        with self.file.position_lock:
            self.file.seek(self._pos)
            data = self.file.read(s)

            if not data:
                return b""

            read = len(data)
            self._pos += read

        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        """
        Set the position of the stream at `offset`, starting depending on `whence`.
        :param offset: offset from the position depending on the whence
        :param whence: can be 0, 1 or 2 - 0 meaning beginning of stream, 1 current position and 2 end of the stream
        :return: the position after seeking, from beginning of the stream
        """
        with self.file.position_lock:
            self._pos = self.file.seek(offset, whence)

        return self._pos

    def truncate(self, size: int = None) -> int:
        """
        Resize the stream to the given size in bytes (or the current position if size is not specified).
        The current stream position isn’t changed. This resizing can extend or reduce the current file size.
        :param size: size to resize the stream to, or position if not given
        :return: the new file size
        """
        if self._mode != "w":
            raise UnsupportedOperation("S3 object is not in write mode")

        with self.file.position_lock:
            truncate = self.file.truncate(size)
            self.s3_object.internal_last_modified = (
                self.file.internal_last_modified
            ) = time.time_ns()
            return truncate

    def write(self, stream: IO[bytes] | "EphemeralS3StoredObject" | LimitedStream) -> int:
        """
        Read from the `stream` parameter into the underlying fileobject. This will truncate the fileobject before
        writing, effectively copying the stream into the fileobject. While iterating, it will also calculate the MD5
        hash of the stream, and its checksum value if the S3Object has a checksum algorithm set.
        This method can directly take an EphemeralS3StoredObject as input, and will use its own locking system to
        prevent concurrent write access while iterating over the stream input.
        :param stream: can be a regular IO[bytes] or an EphemeralS3StoredObject
        :return: number of bytes written
        """
        if self._mode != "w":
            raise UnsupportedOperation("S3 object is not in write mode")

        if stream is None:
            stream = BytesIO()

        if self.s3_object.checksum_algorithm:
            self.checksum_hash = get_s3_checksum(self.s3_object.checksum_algorithm)

        file = self.file
        with file.position_lock:
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
            self._etag = self.s3_object.etag = etag
            self.s3_object.internal_last_modified = (
                self.file.internal_last_modified
            ) = time.time_ns()

            self._pos = file.seek(0)

        return self.size

    def append(self, part: "EphemeralS3StoredObject") -> int:
        """
        Append the EphemeralS3StoredObject data into the underlying fileobject. Used with Multipart Upload to
        assemble parts into the final S3StoredObject.
        :param part: EphemeralS3StoredObject
        :return: number of written bytes
        """
        if self._mode != "w":
            raise UnsupportedOperation("S3 object is not in write mode")

        read = 0
        while data := part.read(S3_CHUNK_SIZE):
            self.file.write(data)
            read += len(data)

        self.size += read
        self.s3_object.size = self.size
        self.s3_object.internal_last_modified = self.file.internal_last_modified = time.time_ns()
        return read

    def close(self):
        """We only release the lock, because closing the underlying file object will delete it"""
        self._lock.release()
        self.closed = True

    @property
    def last_modified(self) -> int:
        return self.file.internal_last_modified

    @property
    def checksum(self) -> Optional[str]:
        """
        Return the object checksum base64 encoded, if the S3Object has a checksum algorithm.
        If the checksum hasn't been calculated, this method will iterate over the file again to recalculate it.
        :return:
        """
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

    @property
    def etag(self) -> str:
        if not self._etag:
            etag = hashlib.md5(usedforsecurity=False)
            original_pos = self._pos
            self._pos = 0
            while data := self.read(S3_CHUNK_SIZE):
                etag.update(data)
            self._pos = original_pos
            self._etag = etag.hexdigest()

        return self._etag

    def __iter__(self) -> Iterator[bytes]:
        """
        This is mostly used as convenience to directly pass this object to a Werkzeug response object, hiding the
        iteration locking logic.
        The caller needs to call `close()` once it is done to release the lock.
        :return:
        """
        while data := self.read(S3_CHUNK_SIZE):
            if not data:
                return b""

            yield data


class EphemeralS3StoredMultipart(S3StoredMultipart):
    upload_dir: str
    _s3_store: "EphemeralS3ObjectStore"
    parts: dict[PartNumber, LockedSpooledTemporaryFile]

    def __init__(
        self,
        s3_store: "EphemeralS3ObjectStore",
        bucket: BucketName,
        s3_multipart: S3Multipart,
        upload_dir: str,
    ):
        super().__init__(s3_store=s3_store, bucket=bucket, s3_multipart=s3_multipart)
        self.upload_dir = upload_dir

    def open(self, s3_part: S3Part, mode: Literal["r", "w"] = "r") -> EphemeralS3StoredObject:
        """
        Returns an EphemeralS3StoredObject for an S3Part, allowing direct access to the object. This will add a part
        into the Multipart collection. We can directly store the EphemeralS3Stored Object in the collection, as S3Part
        cannot be accessed/read directly from the API.
        :param s3_part: S3Part object
        :param mode: opening mode, "read" or "write"
        :return: EphemeralS3StoredObject, most often to directly `write` into it.
        """
        if not (file := self.parts.get(s3_part.part_number)):
            file = LockedSpooledTemporaryFile(dir=self.upload_dir, max_size=S3_MAX_FILE_SIZE_BYTES)
            self.parts[s3_part.part_number] = file

        return EphemeralS3StoredObject(s3_part, file, mode=mode)

    def remove_part(self, s3_part: S3Part):
        """
        Remove a part from the Multipart collection.
        :param s3_part: S3Part
        :return:
        """
        stored_part_file = self.parts.pop(s3_part.part_number, None)
        if stored_part_file:
            stored_part_file.close()

    def complete_multipart(self, parts: list[S3Part]) -> None:
        """
        Takes a list of parts numbers, and will iterate over it to assemble all parts together into a single
        EphemeralS3StoredObject containing all those parts.
        :param parts: list of PartNumber
        :return: the resulting EphemeralS3StoredObject
        """
        with self._s3_store.open(
            self.bucket, self.s3_multipart.object, mode="w"
        ) as s3_stored_object:
            # reset the file to overwrite
            s3_stored_object.seek(0)
            s3_stored_object.truncate()
            for s3_part in parts:
                with self.open(s3_part, mode="r") as stored_part:
                    s3_stored_object.append(stored_part)

    def close(self):
        """
        Iterates over all parts of the collection to close them and clean them up. Closing a part will delete it.
        :return:
        """
        for stored_part_file in self.parts.values():
            stored_part_file.close()
        self.parts.clear()

    def copy_from_object(
        self,
        s3_part: S3Part,
        src_bucket: BucketName,
        src_s3_object: S3Object,
        range_data: Optional[ObjectRange],
    ) -> None:
        """
        Create and add an EphemeralS3StoredObject to the Multipart collection, with an S3Object as input. This will
        take a slice of the S3Object to create a part.
        :param s3_part: the part which will contain the S3 Object slice
        :param src_bucket: the bucket where the source S3Object resides
        :param src_s3_object: the source S3Object
        :param range_data: the range data from which the S3Part will copy its data.
        :return: the EphemeralS3StoredObject representing the stored part
        """
        with self._s3_store.open(
            src_bucket, src_s3_object, mode="r"
        ) as src_stored_object, self.open(s3_part, mode="w") as stored_part:
            if not range_data:
                stored_part.write(src_stored_object)
                return

            object_slice = LimitedStream(src_stored_object, range_data=range_data)
            stored_part.write(object_slice)


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

    root_directory: str

    def __init__(self, root_directory: str = None):
        self._filesystem: dict[BucketName, BucketTemporaryFileSystem] = defaultdict(
            lambda: {"keys": {}, "multiparts": {}}
        )
        # namespace the EphemeralS3ObjectStore artifacts under a single root directory, under gettempdir() if not
        # provided
        if not root_directory:
            root_directory = mkdtemp()

        self.root_directory = root_directory
        self._lock_multipart_create = threading.RLock()

    def open(
        self, bucket: BucketName, s3_object: S3Object, mode: Literal["r", "w"] = "r"
    ) -> EphemeralS3StoredObject:
        """
        Returns a EphemeralS3StoredObject from an S3Object, a wrapper around an underlying fileobject underneath,
        exposing higher level actions for the provider to interact with. This allows the provider to store data for an
        S3Object.
        :param bucket: the S3Object bucket
        :param s3_object: an S3Object
        :param mode: read or write mode for the object to open
        :return: EphemeralS3StoredObject
        """
        key = self._key_from_s3_object(s3_object)
        if not (file := self._get_object_file(bucket, key)):
            bucket_tmp_dir = os.path.join(self.root_directory, bucket)
            file = LockedSpooledTemporaryFile(dir=bucket_tmp_dir, max_size=S3_MAX_FILE_SIZE_BYTES)
            self._filesystem[bucket]["keys"][key] = file

        return EphemeralS3StoredObject(s3_object=s3_object, file=file, mode=mode)

    def remove(self, bucket: BucketName, s3_object: S3Object | list[S3Object]):
        """
        Remove the underlying data of an S3Object.
        :param bucket: the S3Object bucket
        :param s3_object: S3Object to remove. This can also take a list of S3Objects
        :return:
        """
        if not isinstance(s3_object, list):
            s3_object = [s3_object]

        if keys := self._filesystem.get(bucket, {}).get("keys", {}):
            for obj in s3_object:
                key = self._key_from_s3_object(obj)
                file = keys.pop(key, None)
                if file:
                    file.close()

    def copy(
        self,
        src_bucket: BucketName,
        src_object: S3Object,
        dest_bucket: BucketName,
        dest_object: S3Object,
    ) -> EphemeralS3StoredObject:
        """
        Copy an S3Object into another one. This will copy the underlying data inside another.
        :param src_bucket: the source bucket
        :param src_object: the source S3Object
        :param dest_bucket: the destination bucket
        :param dest_object: the destination S3Object
        :return: the destination EphemeralS3StoredObject
        """
        # If this is an in-place copy, directly return the EphemeralS3StoredObject of the destination S3Object, no need
        # to copy the underlying data.
        if src_bucket == dest_bucket and src_object.key == dest_object.key:
            return self.open(dest_bucket, dest_object, mode="r")

        with self.open(src_bucket, src_object, mode="r") as src_stored_object:
            dest_stored_object = self.open(dest_bucket, dest_object, mode="w")
            dest_stored_object.write(src_stored_object)

        return dest_stored_object

    def get_multipart(
        self, bucket: BucketName, s3_multipart: S3Multipart
    ) -> EphemeralS3StoredMultipart:
        # We need to lock this block, because we could have concurrent requests trying to access the same multipart
        # and both creating it at the same time, returning 2 different entities and overriding one
        with self._lock_multipart_create:
            if not (multipart := self._get_multipart(bucket, s3_multipart.id)):
                upload_dir = self._create_upload_directory(bucket, s3_multipart.id)
                multipart = EphemeralS3StoredMultipart(self, bucket, s3_multipart, upload_dir)
                self._filesystem[bucket]["multiparts"][s3_multipart.id] = multipart

        return multipart

    def remove_multipart(self, bucket: BucketName, s3_multipart: S3Multipart):
        if multiparts := self._filesystem.get(bucket, {}).get("multiparts", {}):
            if multipart := multiparts.pop(s3_multipart.id, None):
                multipart.close()
        self._delete_upload_directory(bucket, s3_multipart.id)

    def create_bucket(self, bucket: BucketName):
        mkdir(os.path.join(self.root_directory, bucket))

    def delete_bucket(self, bucket: BucketName):
        if self._filesystem.pop(bucket, None):
            rmtree(os.path.join(self.root_directory, bucket))

    def close(self):
        """
        Close the Store and clean up all underlying objects. This will effectively remove all data from the filesystem
        and memory.
        :return:
        """
        for bucket in self._filesystem.values():
            if keys := bucket.get("keys"):
                for file in keys.values():
                    file.close()
                keys.clear()

            if multiparts := bucket.get("multiparts"):
                for multipart in multiparts.values():
                    multipart.close()
                multiparts.clear()

    def reset(self):
        self.close()

    @staticmethod
    def _key_from_s3_object(s3_object: S3Object) -> str:
        return str(hash(f"{s3_object.key}?{s3_object.version_id or 'null'}"))

    def _get_object_file(self, bucket: BucketName, key: str) -> LockedSpooledTemporaryFile | None:
        return self._filesystem.get(bucket, {}).get("keys", {}).get(key)

    def _get_multipart(self, bucket: BucketName, upload_key: str) -> S3StoredMultipart | None:
        return self._filesystem.get(bucket, {}).get("multiparts", {}).get(upload_key)

    def _create_upload_directory(
        self, bucket_name: BucketName, upload_id: MultipartUploadId
    ) -> str:
        """
        Create a temporary directory inside a bucket, representing a multipart upload, holding its parts
        :param bucket_name: the bucket where the multipart upload resides
        :param upload_id: the multipart upload id
        :return: the full part of the upload, where the parts will live
        """
        upload_tmp_dir = os.path.join(self.root_directory, bucket_name, upload_id)
        mkdir(upload_tmp_dir)
        return upload_tmp_dir

    def _delete_upload_directory(self, bucket_name: BucketName, upload_id: MultipartUploadId):
        """
        Delete the temporary directory representing a multipart upload
        :param bucket_name: the multipart upload bucket
        :param upload_id: the multipart upload id
        :return:
        """
        upload_tmp_dir = os.path.join(self.root_directory, bucket_name, upload_id)
        if upload_tmp_dir:
            rmtree(upload_tmp_dir, ignore_errors=True)
