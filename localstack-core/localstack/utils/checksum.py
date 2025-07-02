import hashlib
import logging
import os
import re
import tempfile
from abc import ABC, abstractmethod

from localstack.utils.files import load_file, rm_rf

# Setup logger
LOG = logging.getLogger(__name__)


class ChecksumException(Exception):
    """Base exception for checksum errors."""

    pass


class ChecksumFormat(ABC):
    """Abstract base class for checksum format parsers."""

    @abstractmethod
    def can_parse(self, content: str) -> bool:
        """
        Check if this parser can handle the given content.

        :param content: The content to check
        :return: True if parser can handle content, False otherwise
        """
        pass

    @abstractmethod
    def parse(self, content: str) -> dict[str, str]:
        """
        Parse the content and return filename to checksum mapping.

        :param content: The content to parse
        :return: Dictionary mapping filenames to checksums
        """
        pass


class StandardFormat(ChecksumFormat):
    """
    Handles standard checksum format.

    Supports formats like:

    * ``checksum  filename``
    * ``checksum *filename``
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        for line in lines[:5]:  # Check first 5 lines
            if re.match(r"^[a-fA-F0-9]{32,128}\s+\S+", line.strip()):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Match: checksum (whitespace) filename
            match = re.match(r"^([a-fA-F0-9]{32,128})\s+(\*?)(.+)$", line)
            if match:
                checksum, star, filename = match.groups()
                checksums[filename.strip()] = checksum.lower()

        return checksums


class BSDFormat(ChecksumFormat):
    """
    Handles BSD-style checksum format.

    Format: ``SHA512 (filename) = checksum``
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        for line in lines[:5]:
            if re.match(r"^(MD5|SHA1|SHA256|SHA512)\s*\(.+\)\s*=\s*[a-fA-F0-9]+", line):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Match: ALGORITHM (filename) = checksum
            match = re.match(r"^(MD5|SHA1|SHA256|SHA512)\s*\((.+)\)\s*=\s*([a-fA-F0-9]+)$", line)
            if match:
                algo, filename, checksum = match.groups()
                checksums[filename.strip()] = checksum.lower()

        return checksums


class ApacheBSDFormat(ChecksumFormat):
    """
    Handles Apache's BSD-style format with split checksums.

    Format::

        filename: CHECKSUM_PART1
                 CHECKSUM_PART2
                 CHECKSUM_PART3
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        if lines and ":" in lines[0]:
            # Check if it looks like filename: hex_data
            parts = lines[0].split(":", 1)
            if len(parts) == 2 and re.search(r"[a-fA-F0-9\s]+", parts[1]):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        lines = content.strip().split("\n")

        current_file = None
        checksum_parts = []

        for line in lines:
            if ":" in line and not line.startswith(" "):
                # New file entry
                if current_file and checksum_parts:
                    # Save previous file's checksum
                    full_checksum = "".join(checksum_parts).replace(" ", "").lower()
                    if re.match(r"^[a-fA-F0-9]+$", full_checksum):
                        checksums[current_file] = full_checksum

                # Start new file
                parts = line.split(":", 1)
                current_file = parts[0].strip()
                checksum_part = parts[1].strip()
                checksum_parts = [checksum_part]
            elif line.strip() and current_file:
                # Continuation of checksum
                checksum_parts.append(line.strip())

        # Don't forget the last file
        if current_file and checksum_parts:
            full_checksum = "".join(checksum_parts).replace(" ", "").lower()
            if re.match(r"^[a-fA-F0-9]+$", full_checksum):
                checksums[current_file] = full_checksum

        return checksums


class ChecksumParser:
    """Main parser that tries different checksum formats."""

    def __init__(self):
        """Initialize parser with available format parsers."""
        self.formats = [
            StandardFormat(),
            BSDFormat(),
            ApacheBSDFormat(),
        ]

    def parse(self, content: str) -> dict[str, str]:
        """
        Try each format parser until one works.

        :param content: The content to parse
        :return: Dictionary mapping filenames to checksums
        """
        for format_parser in self.formats:
            if format_parser.can_parse(content):
                result = format_parser.parse(content)
                if result:
                    return result

        return {}


def parse_checksum_file_from_url(checksum_url: str) -> dict[str, str]:
    """
    Parse a SHA checksum file from a URL using multiple format parsers.

    :param checksum_url: URL of the checksum file
    :return: Dictionary mapping filenames to checksums
    """
    # import here to avoid circular dependency issues
    from localstack.utils.http import download

    checksum_name = os.path.basename(checksum_url)
    checksum_path = os.path.join(tempfile.gettempdir(), checksum_name)
    try:
        download(checksum_url, checksum_path)
        checksum_content = load_file(checksum_path)

        parser = ChecksumParser()
        checksums = parser.parse(checksum_content)

        return checksums
    finally:
        rm_rf(checksum_path)


def calculate_file_checksum(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate checksum of a local file.

    :param file_path: Path to the file
    :param algorithm: Hash algorithm to use
    :return: Calculated checksum as hexadecimal string

    note: Supported algorithms: 'md5', 'sha1', 'sha256', 'sha512'
    """
    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, "rb") as f:
        # Read file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def verify_local_file_with_checksum_url(file_path: str, checksum_url: str, filename=None) -> bool:
    """
    Verify a local file against checksums from an online checksum file.

    :param file_path: Path to the local file to verify
    :param checksum_url: URL of the checksum file
    :param filename: Filename to look for in checksum file (defaults to basename of file_path)
    :return: True if verification succeeds, False otherwise

    note: The algorithm is automatically detected based on checksum length:

       * 32 characters: MD5
       * 40 characters: SHA1
       * 64 characters: SHA256
       * 128 characters: SHA512
    """
    # Get checksums from URL
    LOG.debug("Fetching checksums from %s...", checksum_url)
    checksums = parse_checksum_file_from_url(checksum_url)

    if not checksums:
        raise ChecksumException(f"No checksums found in {checksum_url}")

    # Determine filename to look for
    if filename is None:
        filename = os.path.basename(file_path)

    # Find checksum for our file
    if filename not in checksums:
        # Try with different path variations
        possible_names = [
            filename,
            os.path.basename(filename),  # just filename without path
            filename.replace("\\", "/"),  # Unix-style paths
            filename.replace("/", "\\"),  # Windows-style paths
        ]

        found = False
        for name in possible_names:
            if name in checksums:
                filename = name
                found = True
                break

        if not found:
            raise ChecksumException(f"Checksum for {filename} not found in {checksum_url}")

    expected_checksum = checksums[filename]

    # Detect algorithm based on checksum length
    checksum_length = len(expected_checksum)
    if checksum_length == 32:
        algorithm = "md5"
    elif checksum_length == 40:
        algorithm = "sha1"
    elif checksum_length == 64:
        algorithm = "sha256"
    elif checksum_length == 128:
        algorithm = "sha512"
    else:
        raise ChecksumException(f"Unsupported checksum length: {checksum_length}")

    # Calculate checksum of local file
    LOG.debug("Calculating %s checksum of %s...", algorithm, file_path)
    calculated_checksum = calculate_file_checksum(file_path, algorithm)

    is_valid = calculated_checksum == expected_checksum.lower()

    if not is_valid:
        LOG.error(
            "Checksum mismatch for %s: calculated %s, expected %s",
            file_path,
            calculated_checksum,
            expected_checksum,
        )
        raise ChecksumException(
            f"Checksum mismatch for {file_path}: calculated {calculated_checksum}, expected {expected_checksum}"
        )
    LOG.debug("Checksum verification successful for %s", file_path)

    # Compare checksums
    return calculated_checksum == expected_checksum.lower()
