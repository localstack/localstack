def handler(event, context):
    # Returns > 256 KB of data as a UTF-8 encoded string.
    size_in_bytes = 257 * 1024
    ascii_string = "a" * size_in_bytes
    utf8_encoded_string = ascii_string.encode("utf-8")
    return utf8_encoded_string
