import base64
import bisect
import codecs
import copy
import hashlib
import itertools
import logging
from collections.abc import Iterator
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

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    CopyObjectOutput,
    CopyObjectRequest,
    InvalidStorageClass,
    NoSuchUpload,
    PutObjectOutput,
    PutObjectRequest,
    UploadPartOutput,
    UploadPartRequest,
)
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.services.s3.models import get_moto_s3_backend
from localstack.services.s3.provider import S3Provider
from localstack.services.s3.utils import (
    InvalidRequest,
    extract_bucket_key_version_id_from_copy_source,
    get_bucket_from_moto,
    get_key_from_moto_bucket,
    get_s3_checksum,
    validate_kms_key_id,
)
from localstack.utils.aws import arns
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

S3_UPLOAD_PART_MIN_SIZE = 5242880  # for parity with AWS?
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

MOTO_S3_DEFAULT_KEY_BUFFER_SIZE = str(S3_MAX_FILE_SIZE_BYTES)

CHUNK_SIZE = 1024 * 4


class S3ProviderStream(S3Provider):
    def on_after_init(self):
        super().on_after_init()
        apply_stream_patches()

    @handler("PutObject", expand=False)
    def put_object(
        self,
        context: RequestContext,
        request: PutObjectRequest,
    ) -> PutObjectOutput:
        # TODO: it seems AWS uses AES256 encryption by default now, starting January 5th 2023
        # note: etag do not change after encryption
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html

        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])

        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, moto_bucket)

        try:
            request_without_body = copy.copy(request)
            body = request_without_body.pop("Body", BytesIO(b""))
            request_without_body["Body"] = BytesIO(b"")
            checksums_keys = {
                key for key in request_without_body.keys() if key.startswith("Checksum")
            }
            for checksum_key in checksums_keys:
                request_without_body.pop(checksum_key)

            response: PutObjectOutput = call_moto_with_request(
                context,
                request_without_body,
                override_headers=True,
            )
        except CommonServiceException as e:
            # missing attributes in exception
            if e.code == "InvalidStorageClass":
                raise InvalidStorageClass(
                    "The storage class you specified is not valid",
                    StorageClassRequested=request.get("StorageClass"),
                )
            raise

        # moto interprets the Expires in query string for presigned URL as an Expires header and use it for the object
        # we set it to the correctly parsed value in Request, else we remove it from moto metadata
        # we are getting the last set key here so no need for versionId when getting the key
        key_object = get_key_from_moto_bucket(moto_bucket, key=request["Key"])
        key_object: StreamedFakeKey
        checksum_algorithm = request.get("ChecksumAlgorithm")
        # checksum_header = f"Checksum{checksum_algorithm.upper()}" if checksum_algorithm else None
        checksum_value = (
            request.get(f"Checksum{checksum_algorithm.upper()}") if checksum_algorithm else None
        )
        key_object.checksum_value = checksum_value or None
        key_object.checksum_algorithm = checksum_algorithm

        headers = context.request.headers
        content_sha_256 = context.request.headers.get("x-amz-content-sha256") or ""
        try:
            if content_sha_256.startswith("STREAMING-"):
                # this is a chunked request, we need to properly decode it while setting the key value
                decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
                key_object.set_value_from_chunked_payload(body, decoded_content_length)

            else:
                # set the stream to be the value of the key
                key_object.value = body
        except ChecksumInvalid:
            raise InvalidRequest(
                f"Value for x-amz-checksum-{checksum_algorithm.lower()} header is invalid."
            )
        # the etag is recalculated
        response["ETag"] = key_object.etag

        if expires := request.get("Expires"):
            key_object.set_expiry(expires)
        elif "expires" in key_object.metadata:  # if it got added from query string parameter
            metadata = {k: v for k, v in key_object.metadata.items() if k != "expires"}
            key_object.set_metadata(metadata, replace=True)

        if key_object.kms_key_id:
            # set the proper format of the key to be an ARN
            key_object.kms_key_id = arns.kms_key_arn(
                key_id=key_object.kms_key_id,
                account_id=moto_bucket.account_id,
                region_name=moto_bucket.region_name,
            )
            response["SSEKMSKeyId"] = key_object.kms_key_id

        if key_object.checksum_algorithm:
            response[f"Checksum{key_object.checksum_algorithm.upper()}"] = key_object.checksum_value

        self._notify(context)
        return response

    @handler("CopyObject", expand=False)
    def copy_object(
        self,
        context: RequestContext,
        request: CopyObjectRequest,
    ) -> CopyObjectOutput:
        moto_backend = get_moto_s3_backend(context)
        dest_moto_bucket = get_bucket_from_moto(moto_backend, bucket=request["Bucket"])
        if not config.S3_SKIP_KMS_KEY_VALIDATION and (sse_kms_key_id := request.get("SSEKMSKeyId")):
            validate_kms_key_id(sse_kms_key_id, dest_moto_bucket)

        response: CopyObjectOutput = call_moto(context)

        # moto does not copy all attributes of the key
        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request["CopySource"]
        )
        src_moto_bucket = get_bucket_from_moto(moto_backend, bucket=src_bucket)
        source_key_object = get_key_from_moto_bucket(
            src_moto_bucket, key=src_key, version_id=src_version_id
        )

        checksum_algorithm = (
            request.get("ChecksumAlgorithm") or source_key_object.checksum_algorithm
        )
        if checksum_algorithm:
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested)
            dest_key_object = get_key_from_moto_bucket(dest_moto_bucket, key=request["Key"])
            dest_key_object.checksum_algorithm = checksum_algorithm

            if not source_key_object.checksum_value:
                stream_value = source_key_object.value
                checksum = get_s3_checksum(checksum_algorithm)

                while data := stream_value.read(4096):
                    checksum.update(data)

                calculated_checksum = base64.b64encode(checksum.digest()).decode()
                dest_key_object.checksum_value = calculated_checksum
            else:
                dest_key_object.checksum_value = source_key_object.checksum_value
            dest_key_object.checksum_algorithm = checksum_algorithm

            response["CopyObjectResult"][
                f"Checksum{checksum_algorithm.upper()}"
            ] = dest_key_object.checksum_value  # noqa

        self._notify(context)
        return response

    @handler("UploadPart", expand=False)
    def upload_part(self, context: RequestContext, request: UploadPartRequest) -> UploadPartOutput:
        bucket_name = request["Bucket"]
        moto_backend = get_moto_s3_backend(context)
        moto_bucket = get_bucket_from_moto(moto_backend, bucket_name)
        if not (upload_id := request.get("UploadId")) in moto_bucket.multiparts:
            raise NoSuchUpload(
                "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
                UploadId=upload_id,
            )
        elif request.get("PartNumber", 0) < 1:
            # TODO: find the right exception for this?
            raise NoSuchUpload()

        key = moto_backend.upload_part(
            bucket_name, upload_id, request.get("PartNumber"), request.get("Body")
        )
        response = UploadPartOutput(ETag=key.etag)

        if key.checksum_algorithm is not None:
            response[f"Checksum{key.checksum_algorithm.upper()}"] = key.checksum_value

        if key.encryption is not None:
            response["ServerSideEncryption"] = key.encryption
            if key.encryption == "aws:kms" and key.kms_key_id is not None:
                response["SSEKMSKeyId"] = key.encryption

        if key.encryption == "aws:kms" and key.bucket_key_enabled is not None:
            response["BucketKeyEnabled"] = key.bucket_key_enabled

        return response


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
        self._base_stream.seek(self._pos)

        if not s or s < 0:
            amount = self._length
        else:
            amount = min(self._length, s)

        data = self._base_stream.read(amount)
        if not data:
            return b""
        read_amount = len(data)
        self._length -= read_amount
        self._pos += read_amount

        return data

    def readable(self) -> bool:
        return True

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

        with self.lock:
            self._value_buffer.seek(0)
            self._value_buffer.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
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

            if self.checksum_value and self.checksum_value != calculated_checksum:
                self.dispose()
                raise ChecksumInvalid(self.checksum_algorithm)

            if etag_empty:
                self._etag = etag.hexdigest()

            self.contentsize = self._value_buffer.tell()
            self._value_buffer.seek(0)

    def set_value_from_chunked_payload(self, new_value: IO[bytes], content_length: int):
        etag_empty = not self._etag or self._etag == "d41d8cd98f00b204e9800998ecf8427e"
        with self.lock:
            self._value_buffer.seek(0)
            self._value_buffer.truncate()
            # We have 2 cases:
            # The client gave a checksum value, we will need to compute the value and validate it against
            # or the client have an algorithm value only and we need to compute the checksum
            checksum = None
            calculated_checksum = None
            if self.checksum_algorithm:
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
                        LOG.warning("The S3 object body didn't conform to the aws-chunk format")
                except ValueError:
                    trailing_headers.append(next_line.strip())

                # try for trailing headers after
                while line := new_value.readline():
                    trailing_header = line.strip()
                    if trailing_header:
                        trailing_headers.append(trailing_header)

            # look for the checksum header in the trailing headers
            # TODO: we could get the header key from x-amz-trailer as well
            for trailing_header in trailing_headers:
                try:
                    header_key, header_value = trailing_header.decode("utf-8").split(
                        ":", maxsplit=1
                    )
                    if header_key.lower() == f"x-amz-checksum-{self.checksum_algorithm}".lower():
                        self.checksum_value = header_value
                except (IndexError, ValueError, AttributeError):
                    continue

            if self.checksum_algorithm:
                calculated_checksum = base64.b64encode(checksum.digest()).decode()

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

    def complete(self, body: Iterator[Tuple[int, str]]) -> Tuple[SpooledTemporaryFile, str]:
        decode_hex = codecs.getdecoder("hex_codec")

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

        existing_keys = bucket.keys.getlist(key_name, [])
        if bucket.is_versioned:
            keys = existing_keys + [new_key]
        else:
            keys = [new_key]
        bucket.keys.setlist(key_name, keys)

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

    @patch(s3_responses.S3Response.key_response)
    def _fix_key_response(fn, self, *args, **kwargs):
        """Return an iterator from the stream value in `key_value`"""
        status_code, resp_headers, key_value = fn(self, *args, **kwargs)
        content = get_generator_from_stream(key_value)
        return status_code, resp_headers, content

    @patch(s3_responses.S3Response._handle_range_header, pass_target=False)
    def _handle_range_header(
        self, request: Any, response_headers: dict[str, Any], response_content: Any
    ) -> TYPE_RESPONSE:
        is_streamed = isinstance(response_content, SpooledTemporaryFile)
        if is_streamed:
            response_content.seek(0, 2)
            length = response_content.tell()
            response_content.seek(0)
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
            stream = PartialStream(response_content, begin, end)
            content = get_generator_from_stream(stream)
            requested_length = end - begin + 1
            response_headers["content-length"] = requested_length

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
