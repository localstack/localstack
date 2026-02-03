# Code inspired by the standard library ``email.quoprimime.header_encode``, but the safe characters set is different
# in AWS, so we need to override it
import unicodedata
from base64 import b64encode
from email.errors import HeaderParseError
from email.header import decode_header as _decode_header

from localstack.utils.strings import to_str

# Build a mapping of octets to the expansion of that octet.  Since we're only
# going to have 256 of these things, this isn't terribly inefficient
# space-wise. Initialize the map with the full expansion, and then override
# the safe bytes with the more compact form.
_QUOPRI_HEADER_MAP = [f"={c:02X}" for c in range(256)]

_SAFE_HEADERS_CHARS = b"!\"#$%&'()*+,-./0123456789:;<>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^`abcdefghijklmnopqrstuvwxyz{|}~\t"
_NO_ENCODING_CHARS = _SAFE_HEADERS_CHARS + b" _=?"

# For AWS, it seems it uses the std lib "safe body" bytes list which need no encoding.
for c in _SAFE_HEADERS_CHARS:
    _QUOPRI_HEADER_MAP[c] = chr(c)

# Headers have one other special encoding; spaces become underscores.
_QUOPRI_HEADER_MAP[ord(" ")] = "_"


def encode_header_rfc2047(header: str | None) -> str | None:
    if header is None:
        return None

    header_bytes = header.encode("utf-8")
    # When all chars are "safe chars" plus " " and "_", AWS returns it as is.
    # But if " " and "_" are presented in an encoded header, it will encode them as well
    if all(c in _NO_ENCODING_CHARS for c in header_bytes):
        return header

    if "�" in header or any(unicodedata.category(c).startswith("C") for c in header):
        # if there are any character which cannot be printed (not a symbol, but will be escaped with \xNN), we need to
        # base64 encode the header
        # See https://www.unicode.org/reports/tr44/tr44-34.html#General_Category_Values
        encoder = encoder_header_rfc2047_base64
    else:
        encoder = encode_header_rfc2047_quote_printable

    return encoder(header_bytes)


def encode_header_rfc2047_quote_printable(header_bytes: bytes) -> str:
    """
    Encode the header value in an RFC 2047 Quote-printable format. By default, Python would encode it in Base64, but
    AWS encodes it in the QP (a format similar to Quoted-printable, but used for emails).
    This is the same as the standard library ``email.quoprimime.header_encode``, used by ``email.header.Header`` and
    ``email.charset.Charset``, but the list of safe characters that do not need to be encoded is different and not
    overridable.

    See:
    - https://www.rfc-editor.org/rfc/rfc2047.html
    - https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html#UserMetadata
    :param header_bytes: header byte value, UTF-8-encoded
    :return: encoded header value in RFC 2047 Quoted-printable format
    """
    # we use our own safe character map here
    encoded = header_bytes.decode("latin1").translate(_QUOPRI_HEADER_MAP)
    return f"=?UTF-8?Q?{encoded}?="


def encoder_header_rfc2047_base64(header_bytes: bytes) -> str:
    encoded = b64encode(header_bytes).decode("ascii")
    return f"=?UTF-8?B?{encoded}?="


def decode_header_rfc2047(header: str) -> str:
    try:
        header_parts = _decode_header(header)
        return "".join(to_str(part, charset) for part, charset in header_parts)
    except HeaderParseError:
        if header.lower().startswith("=?utf-8?b?"):
            # if the header is badly B64 encoded, AWS will return random data, which we cannot make sense of.
            # we can use the Unicode replacement character instead to indicate an error
            # we return as many replacement chars as there are b64 chars
            replacement_header = "\ufffd" * (len(header) - 13)
            return replacement_header
        return header


def replace_non_iso_8859_1_characters(header: str, repl: str = " ") -> str:
    """
    Sanitize the header value to not contain any character which cannot be encoded to latin-1, to be compatible with
    webservers.
    :param header: header value, UTF-8 encoded
    :param repl: replacement value for latin-1 incompatible char, empty space by default in AWS
    :return: sanitized header value which can be encoded as latin-1
    """
    sanitized_header = header
    while True:
        try:
            sanitized_header.encode("iso-8859-1", errors="strict")
            break
        except UnicodeEncodeError as exc:
            bad_char = sanitized_header[exc.start : exc.end]
            sanitized_header = sanitized_header.replace(bad_char, repl)

    return sanitized_header
