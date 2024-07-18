DROPPED_FROM_INVOCATION_REQUEST_COMMON = [
    "Connection",
    "Content-Length",
    "Content-MD5",
    "Expect",
    "Max-Forwards",
    "Proxy-Authenticate",
    "Server",
    "TE",
    "Transfer-Encoding",
    "Trailer",
    "Upgrade",
    "WWW-Authenticate",
]
DROPPED_FROM_INVOCATION_REQUEST_COMMON_LOWER = [
    header.lower() for header in DROPPED_FROM_INVOCATION_REQUEST_COMMON
]


def should_drop_header_from_invocation(header: str) -> bool:
    """These headers are not making it to the invocation requests. Even Proxy integrations are not sending them."""
    if header.lower() in DROPPED_FROM_INVOCATION_REQUEST_COMMON_LOWER:
        return True
