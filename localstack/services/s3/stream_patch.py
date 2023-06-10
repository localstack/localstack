import base64
import bisect
import codecs
import hashlib
import itertools
import logging
from collections.abc import Iterable, Iterator
from io import BytesIO, RawIOBase
from tempfile import SpooledTemporaryFile
from typing import IO, Any, Optional, Tuple

from moto.core.common_types import TYPE_RESPONSE
from moto.core.utils import unix_time_millis
from moto.moto_api._internal import mock_random as random
from moto.s3 import exceptions as s3_exceptions
from moto.s3 import models as s3_models
from moto.s3 import responses as s3_responses
from moto.s3.utils import clean_key_name
from requests.structures import CaseInsensitiveDict

from localstack.services.s3.utils import get_s3_checksum
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

S3_UPLOAD_PART_MIN_SIZE = 5242880  # for parity with AWS?
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

MOTO_S3_DEFAULT_KEY_BUFFER_SIZE = str(S3_MAX_FILE_SIZE_BYTES)

CHUNK_SIZE = 1024 * 4

# from memory_profiler import profile


class ChecksumInvalid(s3_exceptions.S3ClientError):
    code = 400

    def __init__(self, algorithm: str):
        super().__init__(
            "InvalidRequest",
            f"Value for x-amz-checksum-{algorithm.lower()} header is invalid.",
        )


class PartialStream(RawIOBase):
    def __init__(self, base_stream: IO[bytes], start_byte: int, end_byte: int):
        super().__init__()
        self._base_stream = base_stream
        self._pos = start_byte
        self._length = end_byte - start_byte + 1

    def read(self, s: int = -1) -> bytes | None:
        print(f"reading from base stream {s=}, {self._pos=}, {self._length=}")
        self._base_stream.seek(self._pos)

        if not s or s < 0:
            amount = self._length
        else:
            amount = min(self._length, s)

        data = self._base_stream.read(amount)
        if not data:
            return
        read_amount = len(data)
        self._length -= read_amount
        self._pos += read_amount

        return data

    def tell(self):
        return self._length


class StreamedFakeKey(s3_models.FakeKey):
    def __init__(self, name: str, value: IO[bytes], *args, **kwargs):
        # when we set the value to nothing to first initialize the key for `PutObject` until we pull all logic in the
        # provider
        if not value or isinstance(value, bytes):
            value = BytesIO(value or b"")
        super(StreamedFakeKey, self).__init__(name, value, *args, **kwargs)
        self.is_latest = True

    @property
    def value(self) -> IO[bytes]:
        # TODO: verify this
        self._value_buffer.seek(0)
        return self._value_buffer

    @value.setter
    def value(self, new_value: IO[bytes] | SpooledTemporaryFile):
        etag_empty = not self._etag or self._etag == "d41d8cd98f00b204e9800998ecf8427e"
        # it could come from the already calculated and completed CompleteMultipartUpload
        # in that case, set it directly as the buffer
        if isinstance(new_value, SpooledTemporaryFile):
            self._value_buffer.close()
            self._value_buffer = new_value
            self.contentsize = self._value_buffer.tell()
            self._value_buffer.seek(0)
            return

        # TODO: there can be trailing things in the body
        # depending on headers and checksum
        with self.lock:
            self._value_buffer.seek(0)
            self._value_buffer.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                # TODO: get the proper checksum type to then feed with data
                checksum = get_s3_checksum(self.checksum_algorithm)
            if etag_empty:
                etag = hashlib.md5(usedforsecurity=False)

            while data := new_value.read(CHUNK_SIZE):
                self._value_buffer.write(data)
                if self.checksum_algorithm:
                    checksum.update(data)
                if etag_empty:
                    etag.update(data)

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            # TODO: we might get the value from the last part of the stream, verify this!!!
            if self.checksum_value and self.checksum_value != calculated_checksum:
                self.dispose()
                raise ChecksumInvalid(self.checksum_algorithm)

            if etag_empty:
                self._etag = etag.hexdigest()

            self.contentsize = self._value_buffer.tell()
            self._value_buffer.seek(0)

    def set_value_from_chunked_payload(self, new_value: IO[bytes], content_length: int):
        etag_empty = not self._etag or self._etag == "d41d8cd98f00b204e9800998ecf8427e"
        # TODO: there can be trailing things in the body
        # depending on headers and checksum
        with self.lock:
            self._value_buffer.seek(0)
            self._value_buffer.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
                # TODO: get the proper checksum type to then feed with data
                checksum = get_s3_checksum(self.checksum_algorithm)
            etag = hashlib.md5(usedforsecurity=False)

            written = 0
            while written < content_length:
                line = new_value.readline()
                chunk_length = int(line.split(b";")[0], 16)

                while chunk_length > 0:
                    amount = min(chunk_length, CHUNK_SIZE)
                    data = new_value.read(amount)
                    self._value_buffer.write(data)

                    real_amount = len(data)
                    chunk_length -= real_amount
                    written += real_amount

                    if self.checksum_algorithm:
                        checksum.update(data)
                    etag.update(data)

                # remove trailing \r\n
                new_value.read(2)

            trailing_headers = []
            next_line = new_value.readline()

            if next_line:
                try:
                    chunk_length = int(next_line.split(b";")[0], 16)
                    if chunk_length != 0:
                        print("something is very wrong??")
                    print("last chunk, that's the end boys")
                except ValueError:
                    print("last line is headers already?? could be")
                    trailing_headers.append(next_line)

                # try for trailing headers after
                while line := new_value.readline():
                    trailing_headers.append(line)

                print(trailing_headers)
            # TODO: parse trailing headers for checksum

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

            # TODO: we might get the value from the last part of the stream, verify this!!!
            if self.checksum_value and self.checksum_value != calculated_checksum:
                self.dispose()
                raise ChecksumInvalid(self.checksum_algorithm)

            self._etag = (
                etag.hexdigest() if etag_empty else self._etag
            )  # if it's already set, from CompleteMultipart for example
            self.contentsize = self._value_buffer.tell()
            self._value_buffer.seek(0)


class StreamedFakeMultipart(s3_models.FakeMultipart):
    def __init__(self, *args, **kwargs):
        super(StreamedFakeMultipart, self).__init__(*args, **kwargs)
        self.parts: dict[int, StreamedFakeKey] = {}

    # @profile
    def complete(self, body: Iterator[Tuple[int, str]]) -> Tuple[SpooledTemporaryFile, str]:
        decode_hex = codecs.getdecoder("hex_codec")
        print("completing the multipart")

        total = SpooledTemporaryFile(max_size=S3_MAX_FILE_SIZE_BYTES)
        md5s = bytearray()

        last = None
        count = 0
        for pn, etag in body:
            part = self.parts.get(pn)
            part_etag = None
            if part is not None:
                part_etag = part.etag.replace('"', "")
                etag = etag.replace('"', "")
            if part is None or part_etag != etag:
                total.close()
                raise s3_exceptions.InvalidPart()
            if last is not None and last.contentsize < S3_UPLOAD_PART_MIN_SIZE:
                total.close()
                raise s3_exceptions.EntityTooSmall()

            md5s.extend(decode_hex(part_etag)[0])
            # to not trigger the property every time
            stream_value = part.value
            while data := stream_value.read(CHUNK_SIZE):
                total.write(data)

            last = part
            count += 1

        if count == 0:
            total.close()
            raise s3_exceptions.MalformedXML

        # once we're done and did not encounter an exception, dispose all parts
        for part in self.parts.values():
            part.dispose()

        full_etag = hashlib.md5(usedforsecurity=False)
        full_etag.update(bytes(md5s))
        total.seek(0)

        return total, f"{full_etag.hexdigest()}-{count}"

    # TODO: we might do this in our provider, to properly pass the IO bytes value
    def set_part(self, part_id: int, value: IO[bytes]) -> StreamedFakeKey:
        if part_id < 1:
            raise s3_exceptions.NoSuchUpload(upload_id=part_id)

        key = StreamedFakeKey(
            part_id, value, encryption=self.sse_encryption, kms_key_id=self.kms_key_id
        )
        if part_id in self.parts:
            # We're overwriting the current part - dispose of it first
            self.parts[part_id].dispose()
        self.parts[part_id] = key
        if part_id not in self.partlist:
            bisect.insort(self.partlist, part_id)
        return key


def apply_stream_patches():
    @patch(s3_models.S3Backend.create_multipart_upload, pass_target=False)
    def create_multipart_upload(
        self,
        bucket_name: str,
        key_name: str,
        metadata: CaseInsensitiveDict,
        storage_type: str,
        tags: dict[str, str],
        acl: Optional[s3_models.FakeAcl],
        sse_encryption: str,
        kms_key_id: str,
    ) -> str:
        multipart = StreamedFakeMultipart(
            key_name,
            metadata,
            storage=storage_type,
            tags=tags,
            acl=acl,
            sse_encryption=sse_encryption,
            kms_key_id=kms_key_id,
        )

        bucket = self.get_bucket(bucket_name)
        bucket.multiparts[multipart.id] = multipart
        return multipart.id

    @patch(s3_models.S3Backend.complete_multipart_upload, pass_target=False)
    def complete_multipart_upload(
        self, bucket_name: str, multipart_id: str, body: Iterator[Tuple[int, str]]
    ) -> Tuple[StreamedFakeMultipart, bytes, str]:
        bucket = self.get_bucket(bucket_name)
        multipart = bucket.multiparts[multipart_id]
        filestream, etag = multipart.complete(body)
        if filestream is not None:
            bucket.multiparts.pop(multipart_id, None)
        return multipart, filestream, etag

    @patch(s3_models.S3Backend.upload_part, pass_target=False)
    def upload_part(
        self, bucket_name: str, multipart_id: str, part_id: int, value: IO[bytes]
    ) -> StreamedFakeKey:
        bucket = self.get_bucket(bucket_name)
        multipart = bucket.multiparts[multipart_id]
        return multipart.set_part(part_id, value)

    @patch(s3_models.S3Backend.copy_part, pass_target=False)
    def copy_part(
        self,
        dest_bucket_name: str,
        multipart_id: str,
        part_id: int,
        src_bucket_name: str,
        src_key_name: str,
        src_version_id: str,
        start_byte: int,
        end_byte: int,
    ) -> StreamedFakeKey:
        dest_bucket = self.get_bucket(dest_bucket_name)
        multipart = dest_bucket.multiparts[multipart_id]

        src_part = self.get_object(src_bucket_name, src_key_name, version_id=src_version_id)

        if start_byte is not None:
            src_value = PartialStream(src_part.value, start_byte, end_byte)
        else:
            src_value = src_part.value
        return multipart.set_part(part_id, src_value)

    @patch(s3_models.S3Backend.put_object, pass_target=False)
    def put_object(
        self,
        bucket_name: str,
        key_name: str,
        value: bytes | IO[bytes],
        storage: Optional[str] = None,
        etag: Optional[str] = None,
        multipart: Optional[StreamedFakeMultipart] = None,
        encryption: Optional[str] = None,
        kms_key_id: Optional[str] = None,
        bucket_key_enabled: Any = None,
        lock_mode: Optional[str] = None,
        lock_legal_status: Optional[str] = None,
        lock_until: Optional[str] = None,
        checksum_value: Optional[str] = None,
    ) -> StreamedFakeKey:
        key_name = clean_key_name(key_name)
        if storage is not None and storage not in s3_models.STORAGE_CLASS:
            raise s3_exceptions.InvalidStorageClass(storage=storage)

        bucket = self.get_bucket(bucket_name)

        # getting default config from bucket if not included in put request
        if bucket.encryption:
            bucket_key_enabled = bucket_key_enabled or bucket.encryption["Rule"].get(
                "BucketKeyEnabled", False
            )
            kms_key_id = kms_key_id or bucket.encryption["Rule"][
                "ApplyServerSideEncryptionByDefault"
            ].get("KMSMasterKeyID")
            encryption = (
                encryption
                or bucket.encryption["Rule"]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            )
        if isinstance(value, bytes):
            value = BytesIO(value)

        new_key = StreamedFakeKey(
            name=key_name,
            bucket_name=bucket_name,
            value=value,
            account_id=self.account_id,
            storage=storage,
            etag=etag,
            is_versioned=bucket.is_versioned,
            # AWS uses VersionId=null in both requests and responses
            version_id=str(random.uuid4()) if bucket.is_versioned else "null",
            multipart=multipart,
            encryption=encryption,
            kms_key_id=kms_key_id,
            bucket_key_enabled=bucket_key_enabled,
            lock_mode=lock_mode,
            lock_legal_status=lock_legal_status,
            lock_until=lock_until,
            checksum_value=checksum_value,
        )

        existing_key = bucket.keys.get(key_name)
        if existing_key:
            existing_key.is_latest = False

        bucket.keys[key_name] = new_key

        return new_key

    @patch(s3_models.S3Backend.list_object_versions, pass_target=False)
    def list_object_versions(
        self,
        bucket_name: str,
        delimiter: Optional[str] = None,
        key_marker: Optional[str] = None,
        prefix: str = "",
    ) -> Tuple[list[StreamedFakeKey], list[str], list[s3_models.FakeDeleteMarker]]:
        bucket = self.get_bucket(bucket_name)

        common_prefixes: list[str] = []
        requested_versions: list[StreamedFakeKey] = []
        delete_markers: list[s3_models.FakeDeleteMarker] = []
        all_versions = list(itertools.chain(*(l for key, l in bucket.keys.iterlists())))
        # sort by name, revert last-modified-date
        all_versions.sort(key=lambda r: (r.name, -unix_time_millis(r.last_modified)))
        # last_name = None
        for version in all_versions:
            name = version.name
            # skip all keys that alphabetically come before keymarker
            if key_marker and name < key_marker:
                continue
            # Filter for keys that start with prefix
            if not name.startswith(prefix):
                continue
            # separate keys that contain the same string between the prefix and the first occurrence of the delimiter
            if delimiter and delimiter in name[len(prefix) :]:
                end_of_delimiter = (
                    len(prefix) + name[len(prefix) :].index(delimiter) + len(delimiter)
                )
                prefix_including_delimiter = name[0:end_of_delimiter]
                common_prefixes.append(prefix_including_delimiter)
                continue

            # Differentiate between FakeKey and FakeDeleteMarkers
            if isinstance(version, s3_models.FakeDeleteMarker):
                delete_markers.append(version)
                continue

            requested_versions.append(version)

        common_prefixes = sorted(set(common_prefixes))

        return requested_versions, common_prefixes, delete_markers

    @patch(s3_responses.S3Response._handle_range_header, pass_target=False)
    def _handle_range_header(
        self, request: Any, response_headers: dict[str, Any], response_content: Any
    ) -> TYPE_RESPONSE:
        # TODO: handle range requests a key level and not for everything? would be easier to access key.size??

        is_streamed = isinstance(response_content, SpooledTemporaryFile)
        if is_streamed:
            response_content.seek(0, 2)
            length = response_content.tell()
            response_content.seek(0)
            print(f"{length=}")
        else:
            length = len(response_content)

        last = length - 1
        _, rspec = request.headers.get("range").split("=")
        if "," in rspec:
            raise NotImplementedError("Multiple range specifiers not supported")

        def toint(i: Any) -> Optional[int]:
            return int(i) if i else None

        begin, end = map(toint, rspec.split("-"))
        if begin is not None:  # byte range
            end = last if end is None else min(end, last)
        elif end is not None:  # suffix byte range
            begin = length - min(end, length)
            end = last
        else:
            return 400, response_headers, ""
        if begin < 0 or end > last or begin > min(end, last):
            raise s3_exceptions.InvalidRange(
                actual_size=str(length), range_requested=request.headers.get("range")
            )
        response_headers["content-range"] = f"bytes {begin}-{end}/{length}"

        if not is_streamed:
            content = response_content[begin : end + 1]
            response_headers["content-length"] = len(content)
        else:
            # content = PartialStream(response_content, begin, end)
            requested_length = end - begin + 1
            response_headers["content-length"] = min(requested_length, length - requested_length)

            def get_range() -> Iterable[bytes]:
                # Werkzeug seems to read only 1 byte every time, so we'd rather control the size with an Iterator
                # TODO: I'd rather had the key return the range, but not sure how to do it properly now
                # so we could lock the key stream
                # might + 1 somewhere?
                len_range = requested_length
                pos = begin
                while len_range > 0:
                    response_content.seek(pos)
                    amount = min(len_range, CHUNK_SIZE)
                    data = response_content.read(amount)
                    if not data:
                        return
                    read_amount = len(data)
                    len_range -= read_amount
                    pos += pos + read_amount
                    yield data

            content = get_range()

        return 206, response_headers, content


def get_generator_from_stream(response_content: Any):
    # Werkzeug will only read 1 everytime, so we control how much we return
    if isinstance(response_content, SpooledTemporaryFile):

        def get_data():
            while True:
                data = response_content.read(CHUNK_SIZE)
                if not data:
                    return

                yield data

        return get_data()

    return response_content
