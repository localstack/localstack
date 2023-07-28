import io
from typing import IO, Any, Optional


class AwsChunkedDecoder(io.RawIOBase):
    """
    This helper class takes a IO[bytes] stream, and decodes it on the fly, so that S3 can directly access the stream
    without worrying about implementation details of `aws-chunked`.
    It needs to expose the trailing headers, which will be available once the stream is fully read.
    You can also directly pass the S3 Object, so the stream would set the checksum value once it's done.
    See `aws-chunked` format here: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
    """

    def readable(self):
        return True

    def __init__(
        self, stream: IO[bytes], decoded_content_length: int, s3_object: Optional[Any] = None
    ):
        self._stream = stream

        self._decoded_length = decoded_content_length  # Length of the encoded object
        self._new_chunk = True
        self._end_chunk = False
        self._trailing_set = False
        self._chunk_size = 0
        self._trailing_headers = {}
        self.s3_object = s3_object

    @property
    def trailing_headers(self):
        if not self._trailing_set:
            raise AttributeError(
                "The stream has not been fully read yet, the trailing headers are not available."
            )
        return self._trailing_headers

    def seekable(self):
        return self._stream.seekable()

    def readinto(self, b):
        with memoryview(b) as view, view.cast("B") as byte_view:
            data = self.read(len(byte_view))
            byte_view[: len(data)] = data
        return len(data)

    def read(self, size=-1):
        """
        Read from the underlying stream, and return at most `size` decoded bytes.
        If a chunk is smaller than `size`, we will return less than asked, but we will always return data if there
        are chunks left
        :param size: amount to read, please note that it can return less than asked
        :return: bytes from the underlying stream
        """
        if size < 0:
            return self.readall()

        if not size:
            return b""

        if self._end_chunk:
            # if it's the end of a chunk we need to strip the newline at the end of the chunk
            # before jumping to the new one
            self._strip_chunk_new_lines()
            self._new_chunk = True
            self._end_chunk = False

        if self._new_chunk:
            # If the _new_chunk flag is set, we have to jump to the next chunk, if there's one
            self._get_next_chunk_length()
            self._new_chunk = False

        if self._chunk_size == 0 and self._decoded_length <= 0:
            # If the next chunk is 0, and we decoded everything, try to get the trailing headers
            self._get_trailing_headers()
            if self.s3_object:
                self._set_checksum_value()
            return b""

        # take the minimum account between the requested size, and the left chunk size
        # (to not over read from the chunk)
        amount = min(self._chunk_size, size)
        data = self._stream.read(amount)

        if data == b"":
            raise EOFError("Encoded file ended before the end-of-stream marker was reached")

        read = len(data)
        self._chunk_size -= read
        if self._chunk_size <= 0:
            self._end_chunk = True

        self._decoded_length -= read

        return data

    def _strip_chunk_new_lines(self):
        self._stream.read(2)

    def _get_next_chunk_length(self):
        line = self._stream.readline()
        chunk_length = int(line.split(b";")[0], 16)
        self._chunk_size = chunk_length

    def _get_trailing_headers(self):
        """
        Once the stream content is read, we try to parse the trailing headers.
        """
        # try to get all trailing headers until the end of the stream
        while line := self._stream.readline():
            if trailing_header := line.strip():
                header_key, header_value = trailing_header.decode("utf-8").split(":", maxsplit=1)
                self._trailing_headers[header_key.lower()] = header_value.strip()
        self._trailing_set = True

    def _set_checksum_value(self):
        """
        If an S3 object was passed, we check the presence of the `checksum_algorithm` field, so that we can properly
        get the right checksum header value, and set it directly to the object. It allows us to transparently access
        the provided checksum value by the client in the S3 logic.
        """
        if checksum_algorithm := getattr(self.s3_object, "checksum_algorithm", None):
            self.s3_object.checksum_value = self._trailing_headers.get(
                f"x-amz-checksum-{checksum_algorithm.lower()}"
            )
