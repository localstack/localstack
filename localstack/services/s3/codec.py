import io
from typing import IO


class AwsChunkedDecoder(io.RawIOBase):
    """
    This helper class takes a IO[bytes] stream, and decodes it on the fly, so that S3 can directly access the stream
    without worrying about implementation details of `aws-chunked`.
    It does need access to the trailing headers, which are going to be available once the stream is fully read.
    See `aws-chunked` format here: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
    """

    def readable(self):
        return True

    def __init__(self, stream: IO[bytes], decoded_content_length: int):
        self._stream = stream

        self._decoded_length = decoded_content_length  # Length of the encoded object
        self._new_chunk = True
        self._end_chunk = False
        self._chunk_size = 0
        self._trailing_headers = {}

    @property
    def trailing_headers(self):
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
        :param size:
        :return:
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

        if self._new_chunk:
            # If the _new_chunk flag is set, we have to jump to the next chunk, if there's one
            self._get_next_chunk_length()
            self._new_chunk = False

        if self._chunk_size == 0 and self._decoded_length <= 0:
            # If the next chunk is 0, and we decoded everything, try to get the trailing headers
            self._get_trailing_headers()
            return b""

        # take the minimum account between the requested size, and the left chunk size
        # (to not over read from the chunk)
        amount = min(self._chunk_size, size)
        data = self._stream.read(amount)

        if data == b"":
            raise EOFError("Encoded file ended before the " "end-of-stream marker was reached")

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
        # TODO: try except?
        chunk_length = int(line.split(b";")[0], 16)
        self._chunk_size = chunk_length

    def _get_trailing_headers(self):
        # try to get all trailing headers until the end of the stream
        while line := self._stream.readline():
            if trailing_header := line.strip():
                header_key, header_value = trailing_header.decode("utf-8").split(":", maxsplit=1)
                self._trailing_headers[header_key.lower()] = header_value.strip().lower()
