from localstack.utils.checksum import (
    ApacheBSDFormat,
    BSDFormat,
    ChecksumParser,
    StandardFormat,
)


class TestStandardFormat:
    """Test cases for StandardFormat parser."""

    def test_can_parse_standard_format(self):
        """Test detection of standard checksum format."""
        parser = StandardFormat()

        # Valid standard formats
        assert parser.can_parse("d41d8cd98f00b204e9800998ecf8427e  file.txt")
        assert parser.can_parse(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  test.zip"
        )
        assert parser.can_parse("da39a3ee5e6b4b0d3255bfef95601890afd80709 *binary.exe")

        # Multiple lines
        content = """
d41d8cd98f00b204e9800998ecf8427e  file1.txt
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file2.zip
"""
        assert parser.can_parse(content)

        # Invalid formats
        assert not parser.can_parse("SHA256 (file.txt) = d41d8cd98f00b204e9800998ecf8427e")
        assert not parser.can_parse("file.txt: d41d8cd98f00b204e9800998ecf8427e")
        assert not parser.can_parse("just some random text")
        assert not parser.can_parse("")

    def test_parse_standard_format(self):
        """Test parsing of standard checksum format."""
        parser = StandardFormat()

        content = """
d41d8cd98f00b204e9800998ecf8427e  file1.txt
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file2.zip
# This is a comment
da39a3ee5e6b4b0d3255bfef95601890afd80709 *binary.exe

1234567890abcdef1234567890abcdef12345678  file with spaces.txt
ABCDEF1234567890ABCDEF1234567890ABCDEF12  UPPERCASE.TXT
        """

        result = parser.parse(content)

        assert len(result) == 5
        assert result["file1.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert (
            result["file2.zip"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result["binary.exe"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert result["file with spaces.txt"] == "1234567890abcdef1234567890abcdef12345678"
        assert (
            result["UPPERCASE.TXT"] == "abcdef1234567890abcdef1234567890abcdef12"
        )  # Should be lowercase

    def test_parse_empty_content(self):
        """Test parsing empty content."""
        parser = StandardFormat()
        result = parser.parse("")
        assert result == {}

    def test_parse_comments_only(self):
        """Test parsing content with only comments."""
        parser = StandardFormat()
        content = """
# Comment 1
# Comment 2
        """
        result = parser.parse(content)
        assert result == {}


class TestBSDFormat:
    """Test cases for BSDFormat parser."""

    def test_can_parse_bsd_format(self):
        """Test detection of BSD checksum format."""
        parser = BSDFormat()

        # Valid BSD formats
        assert parser.can_parse("MD5 (file.txt) = d41d8cd98f00b204e9800998ecf8427e")
        assert parser.can_parse(
            "SHA256 (test.zip) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert parser.can_parse(
            "SHA512 (binary.exe) = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        assert parser.can_parse("SHA1 (test) = da39a3ee5e6b4b0d3255bfef95601890afd80709")

        # With spaces
        assert parser.can_parse(
            "SHA256 (file with spaces.txt) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        # Invalid formats
        assert not parser.can_parse("d41d8cd98f00b204e9800998ecf8427e  file.txt")
        assert not parser.can_parse("file.txt: d41d8cd98f00b204e9800998ecf8427e")
        assert not parser.can_parse(
            "SHA3 (file.txt) = d41d8cd98f00b204e9800998ecf8427e"
        )  # Unsupported algorithm

    def test_parse_bsd_format(self):
        """Test parsing of BSD checksum format."""
        parser = BSDFormat()

        content = """
MD5 (file1.txt) = d41d8cd98f00b204e9800998ecf8427e
SHA256 (file2.zip) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA1 (binary.exe) = da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA512 (large.bin) = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
SHA256 (file with (parentheses).txt) = 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
MD5 (UPPERCASE.TXT) = ABCDEF1234567890ABCDEF1234567890
        """

        result = parser.parse(content)

        assert len(result) == 6
        assert result["file1.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert (
            result["file2.zip"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result["binary.exe"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert (
            result["large.bin"]
            == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        assert (
            result["file with (parentheses).txt"]
            == "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        assert result["UPPERCASE.TXT"] == "abcdef1234567890abcdef1234567890"  # Should be lowercase

    def test_parse_mixed_algorithms(self):
        """Test parsing BSD format with mixed algorithms."""
        parser = BSDFormat()

        content = """
MD5 (file1.txt) = d41d8cd98f00b204e9800998ecf8427e
SHA1 (file1.txt) = da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256 (file1.txt) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """

        result = parser.parse(content)

        # Should keep the last one for duplicate filenames
        assert len(result) == 1
        assert (
            result["file1.txt"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )


class TestApacheBSDFormat:
    """Test cases for ApacheBSDFormat parser."""

    def test_can_parse_apache_bsd_format(self):
        """Test detection of Apache BSD checksum format."""
        parser = ApacheBSDFormat()

        # Valid Apache BSD format
        assert parser.can_parse("file.txt: d41d8cd9 8f00b204\n         e9800998 ecf8427e")
        assert parser.can_parse("test.zip: e3b0c442 98fc1c14")
        assert parser.can_parse("file: abcd1234")

        # Invalid formats
        assert not parser.can_parse("d41d8cd98f00b204e9800998ecf8427e  file.txt")
        assert not parser.can_parse("MD5 (file.txt) = d41d8cd98f00b204e9800998ecf8427e")
        assert not parser.can_parse("no colon here")
        assert not parser.can_parse("")

    def test_parse_apache_bsd_format_single_line(self):
        """Test parsing Apache BSD format with single-line checksums."""
        parser = ApacheBSDFormat()

        content = """
file1.txt: d41d8cd98f00b204e9800998ecf8427e
file2.zip: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """

        result = parser.parse(content)

        assert len(result) == 2
        assert result["file1.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert (
            result["file2.zip"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_parse_apache_bsd_format_multi_line(self):
        """Test parsing Apache BSD format with multi-line checksums."""
        parser = ApacheBSDFormat()

        content = """
file1.txt: d41d8cd9 8f00b204
           e9800998 ecf8427e
file2.zip: e3b0c442 98fc1c14 9afbf4c8 996fb924
           27ae41e4 649b934c a495991b 7852b855
binary.exe: da39a3ee 5e6b4b0d
            3255bfef 95601890
            afd80709
single.txt: 1234567890abcdef1234567890abcdef12345678
        """

        result = parser.parse(content)

        assert len(result) == 4
        assert result["file1.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert (
            result["file2.zip"]
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result["binary.exe"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert result["single.txt"] == "1234567890abcdef1234567890abcdef12345678"

    def test_parse_apache_bsd_format_with_spaces(self):
        """Test parsing Apache BSD format with various spacing."""
        parser = ApacheBSDFormat()

        content = """
file with spaces.txt: d41d8cd9 8f00b204
                      e9800998 ecf8427e
another file.zip: ABCD1234 5678ABCD
                  9012ABCD 3456CDEF
        """

        result = parser.parse(content)

        assert len(result) == 2
        assert result["file with spaces.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert (
            result["another file.zip"] == "abcd12345678abcd9012abcd3456cdef"
        )  # Should be lowercase

    def test_parse_apache_bsd_invalid_checksum(self):
        """Test parsing Apache BSD format with invalid checksums."""
        parser = ApacheBSDFormat()

        content = """
valid.txt: d41d8cd98f00b204e9800998ecf8427e
invalid.txt: this is not a valid checksum!
mixed.txt: d41d8cd9 NOTVALID
           e9800998 ecf8427e
        """

        result = parser.parse(content)

        # Only valid checksums should be included
        assert len(result) == 1
        assert result["valid.txt"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert "invalid.txt" not in result
        assert "mixed.txt" not in result


class TestChecksumParser:
    """Test cases for the main ChecksumParser."""

    def test_parse_standard_format(self):
        """Test parser with standard format."""
        parser = ChecksumParser()

        content = "d41d8cd98f00b204e9800998ecf8427e  file.txt"
        result = parser.parse(content)

        assert result["file.txt"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_parse_bsd_format(self):
        """Test parser with BSD format."""
        parser = ChecksumParser()

        content = (
            "SHA256 (file.txt) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        result = parser.parse(content)

        assert (
            result["file.txt"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_parse_apache_bsd_format(self):
        """Test parser with Apache BSD format."""
        parser = ChecksumParser()

        content = """file.txt: d41d8cd9 8f00b204
           e9800998 ecf8427e"""
        result = parser.parse(content)

        assert result["file.txt"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_parse_empty_content(self):
        """Test parser with empty content."""
        parser = ChecksumParser()

        result = parser.parse("")
        assert result == {}

    def test_parse_unknown_format(self):
        """Test parser with unknown format."""
        parser = ChecksumParser()

        content = "This is not a valid checksum format"
        result = parser.parse(content)
        assert result == {}
