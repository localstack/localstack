import base64
import bisect
import codecs
import copy
import datetime
import hashlib
import itertools
import logging
import os
import threading
from collections.abc import Iterator
from io import BytesIO, RawIOBase
from tempfile import SpooledTemporaryFile
from typing import IO, Any, Optional, Tuple
from zoneinfo import ZoneInfo

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
    ChecksumAlgorithm,
    CopyObjectOutput,
    CopyObjectRequest,
    InvalidArgument,
    InvalidStorageClass,
    NoSuchUpload,
    PreconditionFailed,
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
    is_presigned_url_request,
    validate_kms_key_id,
)
from localstack.utils.aws import arns
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

S3_UPLOAD_PART_MIN_SIZE = 5242880  # for parity with AWS?
S3_MAX_FILE_SIZE_BYTES = 512 * 1024

MOTO_S3_DEFAULT_KEY_BUFFER_SIZE = str(S3_MAX_FILE_SIZE_BYTES)

CHUNK_SIZE = 1024 * 16 * 4


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
            # we need to pass the query string parameters to the request to properly recreate it
            if is_presigned_url_request(context):
                for key, value in context.request.args.items():
                    if key in request_without_body:
                        request_without_body[key] = value
                    elif key.startswith("x-amz-meta"):
                        metadata_key = key.removeprefix("x-amz-meta-")
                        request_without_body["Metadata"][metadata_key] = value

            body = request_without_body.pop("Body", BytesIO(b""))
            request_without_body["Body"] = BytesIO(b"")

            response: PutObjectOutput = call_moto_with_request(
                context,
                request_without_body,
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
        # AWS specifies that the `Content-Encoding` should be `aws-chunked`, but some SDK don't set it.
        # Rely on the `x-amz-content-sha256` which is a more reliable indicator that the request is streamed
        content_sha_256 = (headers.get("x-amz-content-sha256") or "").upper()
        if content_sha_256 and content_sha_256.startswith("STREAMING-"):
            # this is a chunked request, we need to properly decode it while setting the key value
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))
            key_object.set_value_from_chunked_payload(body, decoded_content_length)

        else:
            # set the stream to be the value of the key
            key_object.value = body

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

        bucket_lifecycle_configurations = self.get_store(context).bucket_lifecycle_configuration
        if (bucket_lifecycle_config := bucket_lifecycle_configurations.get(request["Bucket"])) and (
            rules := bucket_lifecycle_config.get("Rules")
        ):
            object_tags = moto_backend.tagger.get_tag_dict_for_resource(key_object.arn)
            if expiration_header := self._get_expiration_header(rules, key_object, object_tags):
                response["Expiration"] = expiration_header

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

        src_bucket, src_key, src_version_id = extract_bucket_key_version_id_from_copy_source(
            request["CopySource"]
        )
        src_moto_bucket = get_bucket_from_moto(moto_backend, bucket=src_bucket)
        source_key_object = get_key_from_moto_bucket(
            src_moto_bucket, key=src_key, version_id=src_version_id
        )

        # see https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
        condition = None
        source_object_last_modified = source_key_object.last_modified.replace(
            tzinfo=ZoneInfo("GMT")
        )
        if (cs_if_match := request.get("CopySourceIfMatch")) and source_key_object.etag.strip(
            '"'
        ) != cs_if_match.strip('"'):
            condition = "x-amz-copy-source-If-Match"

        elif (
            cs_id_unmodified_since := request.get("CopySourceIfUnmodifiedSince")
        ) and source_object_last_modified > cs_id_unmodified_since:
            condition = "x-amz-copy-source-If-Unmodified-Since"

        elif (
            cs_if_none_match := request.get("CopySourceIfNoneMatch")
        ) and source_key_object.etag.strip('"') == cs_if_none_match.strip('"'):
            condition = "x-amz-copy-source-If-None-Match"

        elif (
            cs_id_modified_since := request.get("CopySourceIfModifiedSince")
        ) and source_object_last_modified < cs_id_modified_since < datetime.datetime.now(
            tz=ZoneInfo("GMT")
        ):
            condition = "x-amz-copy-source-If-Modified-Since"

        if condition:
            raise PreconditionFailed(
                "At least one of the pre-conditions you specified did not hold",
                Condition=condition,
            )

        response: CopyObjectOutput = call_moto(context)

        # moto does not copy all attributes of the key

        checksum_algorithm = (
            request.get("ChecksumAlgorithm") or source_key_object.checksum_algorithm
        )
        if checksum_algorithm:
            # this is a bug in AWS: it sets the content encoding header to an empty string (parity tested)
            dest_key_object = get_key_from_moto_bucket(dest_moto_bucket, key=request["Key"])
            dest_key_object.checksum_algorithm = checksum_algorithm

            if not source_key_object.checksum_value:
                stream_value: SpooledTemporaryFile = dest_key_object.value
                checksum = get_s3_checksum(checksum_algorithm)

                with dest_key_object.lock:
                    while data := stream_value.read(4096):
                        checksum.update(data)
                    stream_value.seek(0)

                calculated_checksum = base64.b64encode(checksum.digest()).decode()
                dest_key_object.checksum_value = calculated_checksum
            else:
                dest_key_object.checksum_value = source_key_object.checksum_value
            dest_key_object.checksum_algorithm = checksum_algorithm

            if checksum_algorithm == ChecksumAlgorithm.CRC32C:
                # TODO: the logic for rendering the template in moto is the following:
                # if `CRC32` in `key.checksum_algorithm` which is valid for both CRC32 and CRC32C, and will render both
                # remove the key if it's CRC32C.
                response["CopyObjectResult"].pop("ChecksumCRC32", None)

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
        elif (part_number := request.get("PartNumber", 0)) < 1:
            raise InvalidArgument(
                "Part number must be an integer between 1 and 10000, inclusive",
                ArgumentName="partNumber",
                ArgumentValue=part_number,
            )

        body = request.get("Body") or BytesIO()
        decoded_content_length = None
        headers = context.request.headers
        # AWS specifies that the `Content-Encoding` should be `aws-chunked`, but some SDK don't set it.
        # Rely on the `x-amz-content-sha256` which is a more reliable indicator that the request is streamed
        content_sha_256 = (headers.get("x-amz-content-sha256") or "").upper()
        if content_sha_256 and content_sha_256.startswith("STREAMING-"):
            # this is a chunked request, we need to properly decode it while setting the key value
            decoded_content_length = int(headers.get("x-amz-decoded-content-length", 0))

        key = moto_backend.upload_part(
            bucket_name, upload_id, part_number, body, decoded_content_length
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


class PartialStream(RawIOBase):
    """
    This class will take a source stream, and return only a range of it based on the parameters start_byte and end_byte
    """

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


class StreamedFakeKey(s3_models.FakeKey):
    """
    We are overriding the `FakeKey` object from moto to allow streaming input and output instead of loading its full
    value into memory. Most of the changes are related to checksum validation, as we would pass the entire value to the
    checksum before, and we now do it in a chunked manner.
    """

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
        # "d41d8cd98f00b204e9800998ecf8427e" is the ETag of an empty object
        etag_empty = not self._etag or self._etag == "d41d8cd98f00b204e9800998ecf8427e"
        # it could come from the already calculated and completed CompleteMultipartUpload
        # in that case, set it directly as the buffer
        # if the etag is not set, this is the result from CopyObject, in that case we should copy the underlying
        # SpooledTemporaryFile
        if self._etag and isinstance(new_value, SpooledTemporaryFile):
            with self.lock:
                self._value_buffer.close()
                self._value_buffer = new_value
                self._value_buffer.seek(0, os.SEEK_END)
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
                    raise InvalidRequest(
                        f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                    )

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
                raise InvalidRequest(
                    f"Value for x-amz-checksum-{self.checksum_algorithm.lower()} header is invalid."
                )

            self._etag = (
                etag.hexdigest() if etag_empty else self._etag
            )  # if it's already set, from CompleteMultipart for example
            self.contentsize = self._value_buffer.tell()
            self._value_buffer.seek(0)


class StreamedFakeMultipart(s3_models.FakeMultipart):
    """
    We override FakeMultipart to prevent `complete` to load every single part into memory.
    """

    def __init__(self, *args, **kwargs):
        super(StreamedFakeMultipart, self).__init__(*args, **kwargs)
        self.parts: dict[int, StreamedFakeKey] = {}

    def complete(self, body: Iterator[Tuple[int, str]]) -> Tuple[SpooledTemporaryFile, str]:
        decode_hex = codecs.getdecoder("hex_codec")

        # we create a SpooledTemporaryFile which will hold all the parts' data,
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
            with part.lock:
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

    def set_part(
        self, part_id: int, value: IO[bytes], decoded_content_length: int = None
    ) -> StreamedFakeKey:
        if part_id < 1:
            raise s3_exceptions.NoSuchUpload(upload_id=part_id)

        # if the request is not aws-chunked, just use the value setter with the stream
        # else use an empty body as we will use set_value_from_chunked_payload later
        key_value = value if decoded_content_length is None else BytesIO()
        key = StreamedFakeKey(
            part_id, key_value, encryption=self.sse_encryption, kms_key_id=self.kms_key_id
        )
        # as the request is chunked, we then set the chunked payload
        if decoded_content_length:
            key.set_value_from_chunked_payload(value, decoded_content_length)

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
        self,
        bucket_name: str,
        multipart_id: str,
        part_id: int,
        value: IO[bytes],
        decoded_content_length: int = None,
    ) -> StreamedFakeKey:
        bucket = self.get_bucket(bucket_name)
        multipart = bucket.multiparts[multipart_id]
        return multipart.set_part(part_id, value, decoded_content_length)

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
        """
        We are patching `copy_part` to be able to only select a part of a Source object with PartialStream, representing
        only a range of a source stream.
        """
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
        # due to `call_moto_with_request`, it's possible we're passing a double URL encoded key name. Decode it twice
        # if that's the case
        if "%" in key_name:  # FIXME: fix it in `call_moto_with_request`
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

        # small patch to avoid using `copy.deepcopy` in list_object_versions
        # we remove the flag from the last existing key
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
        """
        Small override because moto's `list_object_versions` is using `copy.deepcopy` which is not compatible with
        streams
        """
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

    @patch(s3_responses.S3Response._key_response_get)
    def _fix_key_response_get(
        fn,
        self,
        bucket_name: str,
        query: dict[str, Any],
        key_name: str,
        headers: dict[str, Any],
        *args,
        **kwargs,
    ) -> TYPE_RESPONSE:
        """Return an iterator if the content returned is a `SpooledTemporaryFile`, which indicates that the return
        value is from `GetObject`. We transform this stream into an iterator, to control how much we return"""
        code, response_headers, body = fn(
            self, bucket_name, query, key_name, headers, *args, **kwargs
        )

        if isinstance(body, SpooledTemporaryFile):
            # it means we got a successful `GetObject`, retrieve the key object to get its lock
            version_id = query.get("versionId", [None])[0]
            key = self.backend.get_object(bucket_name, key_name, version_id=version_id)

            # we will handle `range` requests already here as we have access to the `StreamedFakeKey` object and lock
            # as we already return 206, this won't pass to the `_handle_range_header` method again
            # there is some duplication from moto, but it's easier to handle that way
            if code == 200 and (range_header := headers.get("range", "")) != "":
                length = key.size
                last = length - 1
                _, rspec = range_header.split("=")
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
                        actual_size=str(length), range_requested=range_header
                    )
                response_headers["content-range"] = f"bytes {begin}-{end}/{length}"
                requested_length = end - begin + 1
                content = get_range_generator_from_stream(
                    key_stream=key.value,
                    key_lock=key.lock,
                    start=begin,
                    requested_length=requested_length,
                )
                response_headers["content-length"] = requested_length

                return 206, response_headers, content

            body = get_generator_from_key(key_stream=key.value, key_lock=key.lock)

        return code, response_headers, body


def get_generator_from_key(
    key_stream: SpooledTemporaryFile, key_lock: threading.RLock
) -> Iterator[bytes]:
    # Werkzeug will only read 1 everytime, so we control how much we return
    pos = 0
    while True:
        with key_lock:
            key_stream.seek(pos)
            data = key_stream.read(CHUNK_SIZE)
        if not data:
            break
        pos += len(data)
        yield data

    return b""


def get_range_generator_from_stream(
    key_stream: SpooledTemporaryFile,
    key_lock: threading.RLock,
    start: int,
    requested_length: int,
) -> Iterator[bytes]:
    pos = start
    max_length = requested_length
    while True:
        with key_lock:
            key_stream.seek(pos)
            amount = min(max_length, CHUNK_SIZE)
            data = key_stream.read(amount)

        if not data:
            break
        read = len(data)
        pos += read
        max_length -= read
        yield data

    return b""
