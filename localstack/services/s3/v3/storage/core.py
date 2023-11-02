import abc
from io import RawIOBase
from typing import IO, Iterable, Iterator, Optional

from localstack.aws.api.s3 import BucketName, MultipartUploadId, PartNumber
from localstack.services.s3.utils import ObjectRange
from localstack.services.s3.v3.models import S3Multipart, S3Object, S3Part


class LimitedIterableStream(Iterable[bytes]):
    """
    This can limit an Iterable which can return any number of bytes at each iteration, to return a max_length total
    amount of bytes
    """

    def __init__(self, iterable: Iterable[bytes], max_length: int):
        self.iterable = iterable
        self.max_length = max_length

    def __iter__(self):
        for chunk in self.iterable:
            read = len(chunk)
            if self.max_length - read >= 0:
                self.max_length -= read
                yield chunk
            elif self.max_length == 0:
                break
            else:
                yield chunk[: self.max_length]
                break

        return


class LimitedStream(RawIOBase):
    """
    This utility class allows to return a range from the underlying stream representing an S3 Object.
    """

    def __init__(self, base_stream: IO[bytes] | "S3StoredObject", range_data: ObjectRange):
        super().__init__()
        self.file = base_stream
        self._pos = range_data.begin
        self._max_length = range_data.content_length

    def read(self, s: int = -1) -> bytes | None:
        if s is None or s < 0:
            amount = self._max_length
        else:
            amount = min(self._max_length, s)

        self.file.seek(self._pos)
        data = self.file.read(amount)

        if not data:
            return b""
        read_amount = len(data)
        self._max_length -= read_amount
        self._pos += read_amount

        return data


class S3StoredObject(abc.ABC, Iterable[bytes]):
    """
    This abstract class represents the underlying stored data of an S3 object. Its API mimics one of a typical object
    returned by `open`, while allowing easy usage from an S3 perspective.
    """

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

    def truncate(self, size: int = None) -> int:
        pass

    @property
    @abc.abstractmethod
    def checksum(self) -> Optional[str]:
        if not self.s3_object.checksum_algorithm:
            return None

    @property
    @abc.abstractmethod
    def etag(self) -> str:
        pass

    @abc.abstractmethod
    def __iter__(self) -> Iterator[bytes]:
        pass


class S3StoredMultipart(abc.ABC):
    """
    This abstract class represents the collection of stored data of an S3 Multipart Upload. It will collect parts,
    represented as S3StoredObject, and can at some point be assembled into a single S3StoredObject.
    """

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
        range_data: ObjectRange,
    ) -> None:
        pass


class S3ObjectStore(abc.ABC):
    """
    This abstract class is the entrypoint of accessing the storage of S3 data. You can easily open and remove S3 Objects
    as well as directly retrieving a StoredS3Multipart to directly interact with it.
    """

    @abc.abstractmethod
    def open(self, bucket: BucketName, s3_object: S3Object) -> S3StoredObject:
        pass

    @abc.abstractmethod
    def remove(self, bucket: BucketName, s3_object: S3Object | list[S3Object]):
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

    def create_bucket(self, bucket: BucketName):
        pass

    def delete_bucket(self, bucket: BucketName):
        pass

    def flush(self):
        """
        Calling `flush()` should force the `S3ObjectStore` to dump its state to disk, depending on the implementation.
        """
        pass

    def close(self):
        """
        Closing the `S3ObjectStore` allows freeing resources up (like file descriptors for example) when stopping the
        linked provider.
        """
        pass

    def reset(self):
        """
        Resetting the `S3ObjectStore` will delete all the contained resources.
        """
        pass
