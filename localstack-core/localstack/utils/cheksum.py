import re


def parse_sha_file_format(checksum_content: str) -> tuple[str | None, str | None]:
    """
    Parses a SHA file content and returns a checksum SHA hash value.

    :param checksum_content: Path to the SHA file.
    :return: SHA hash value.
    """
    # TODO: extend this to support more formats
    content = checksum_content.lower().splitlines()
    raw_checksum = ""

    # normalize content - handle both single-line and multi-line checksum files
    if len(content) > 1:
        # handle multi-line checksum files where the hash is formatted across multiple lines
        # example format:
        # filename.tgz: xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        #               xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        #               xxxxxxxx xxxxxxxx xxxxxxxx ...
        # this concatenates all lines into: "filename.tgz:  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..."
        for chunk in content:
            raw_checksum += chunk
    else:
        # single-line checksum file - use the line as-is
        # example format:
        # filename.tgz: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        raw_checksum = content[0]

    # Format: filename: checksum (with spaces)
    if ":" in raw_checksum and not raw_checksum.lower().startswith("sha512"):
        file_name, rest = raw_checksum.split(":", 1)
        checksum = re.sub(r"\s+", "", rest.strip())
        return file_name, checksum

    # Format: checksum  filename
    if re.match(r"^[a-f0-9]{64,128}\s{2,}", raw_checksum, re.IGNORECASE):
        file_name = raw_checksum.split()[-1]
        parts = raw_checksum.strip().split()
        checksum = parts[0]
        return file_name, checksum

    # Format: SHA512 (filename) = checksum
    if raw_checksum.lower().startswith("sha512"):
        match = re.match(r"SHA512\s+\((.*?)\)\s+=\s+([a-f0-9]+)", raw_checksum, re.IGNORECASE)
        if match:
            file_name, checksum = match.groups()
            return file_name, checksum

    return None, None


def check_file_integrity(algorithm: str, file_path: str, expected_checksum: str) -> bool:
    """
    Verify the checksum of a file against an expected value.

    :param algorithm: The hashing algorithm to use (e.g., 'sha256', 'sha512').
    :param file_path: Path to the file to verify.
    :param expected_checksum: The expected checksum value.
    :return: True if the checksum matches, False otherwise.
    """
    import hashlib

    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)

    return hash_func.hexdigest() == expected_checksum.lower()
