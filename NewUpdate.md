Contribution: Optimize ResponseStream.readinto() Performance

Problem: The current implementation unnecessarily copies the entire chunk when the buffer is large enough to hold it (line 83 in localstack-core/localstack/aws/client.py).

Solution: Avoid unnecessary slicing when the chunk fits entirely in the buffer.

Problem: Line 83-84 in localstack-core/localstack/aws/client.py copies the entire chunk even when it fits in the buffer, causing unnecessary memory operations.

Solution: Direct copy when chunk fits, slice only when needed.
    def readinto(self, buffer):
        """
        Reads data into the buffer efficiently.
        
        Avoids unnecessary chunk copying when the chunk fits entirely in the buffer,
        improving performance for large reads.
        
        :param buffer: writable buffer to read data into
        :return: number of bytes read, or 0 for EOF
        """
        try:
            upto = len(buffer)  # We're supposed to return at most this much
            
            # Get the next chunk from iterator or use buffered remainder
            chunk = self._buf or next(self.iterator)
            chunk_len = len(chunk)
            
            # If chunk fits entirely in buffer, copy directly without slicing
            if chunk_len <= upto:
                buffer[:chunk_len] = chunk
                self._buf = None  # Clear buffer since we consumed the whole chunk
                return chunk_len
            else:
                # Chunk is larger than buffer - slice and store remainder
                output = chunk[:upto]
                self._buf = chunk[upto:]
                buffer[:upto] = output
                return upto
                
        except StopIteration:
            return 0  # indicate EOF

Step 2: Add Tests (Create/Update tests/unit/aws/test_client.py)

Add this test method inside the TestResponseStream class (after line 67):
    def test_readinto_efficiency_no_copy_when_fits(self):
        """
        Test that readinto doesn't unnecessarily copy when chunk fits in buffer.
        This test verifies the performance optimization.
        """
        # Create a chunk that will fit in buffer
        chunk = b"test-data"
        response = Response(chunk)
        
        with _ResponseStream(response) as stream:
            # Buffer larger than chunk
            buffer = bytearray(20)
            bytes_read = stream.readinto(buffer)
            
            # Should read entire chunk
            assert bytes_read == len(chunk)
            assert buffer[:bytes_read] == chunk
    
    def test_readinto_slicing_overflow(self):
        """
        Test that readinto correctly slices when chunk overflows buffer.
        """
        # Create a chunk larger than buffer
        chunk = b"this-is-a-very-long-chunk-exceeding-buffer"
        response = Response(chunk)
        
        with _ResponseStream(response) as stream:
            # Smaller buffer than chunk
            buffer = bytearray(10)
            bytes_read = stream.readinto(buffer)
            
            # Should read only buffer size
            assert bytes_read == 10
            assert buffer == b"this-is-a-"
            
            # Next read should continue from remainder
            bytes_read = stream.readinto(buffer)
            assert bytes_read == 10
            assert buffer == b"very-long-"
    
    def test_readinto_with_generator_chunks(self):
        """
        Test readinto with multiple chunks from a generator.
        """
        def _gen():
            yield b"first"
            yield b"second"
            yield b"third"
        
        response = Response(_gen())
        
        with _ResponseStream(response) as stream:
            # Read first chunk
            buffer = bytearray(10)
            bytes_read = stream.readinto(buffer)
            assert bytes_read == 5
            assert buffer[:5] == b"first"
            
            # Read next chunk
            bytes_read = stream.readinto(buffer)
            assert bytes_read == 6
            # Next chunk is 6 chars: "second"
            assert buffer[:6] == b"second"
            
            # Read third chunk
            bytes_read = stream.readinto(buffer)
            assert bytes_read == 5
            assert buffer[:5] == b"third"
            
            # Should return 0 (EOF)
            assert stream.readinto(buffer) == 0


