#!/usr/bin/env python

from pathlib import Path
import base64
import json

import requests


def jwt_base64_decode(payload):
    """Decode a Base64 encoded string from a JWT token.

    JWT encodes using the URLSafe base64 algorithm and then removes the
    padding. This function does the opposite: adds the padding back and then
    uses the URLSafe base64 algorithm to decode the string.
    """
    # Thanks Simon Sapin
    # (https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding)
    missing_padding = len(payload) % 4
    if missing_padding:
        payload += "=" * (4 - missing_padding)

    decoded_bytes = base64.urlsafe_b64decode(payload)
    decoded_str = decoded_bytes.decode("utf-8")
    return decoded_str


def handle_input_line(line):
    """This handles one line of input, that should be a JWT token.

    This will first split the token in its 3 components, base64 decode the 2nd
    one that's the payload, json-parse it, and finally print the key
    "profileToken" from that JSON payload.
    """
    _, payload, _ = line.strip().split(".")

    decoded_str = jwt_base64_decode(payload)
    json_payload = json.loads(decoded_str)
    token = json_payload["profileToken"]
    return token


def upload_profile(path: Path) -> str:
    """
    Upload the profile to a public place, and return the URL the profile is viewable from.
    """
    with path.open("rb") as infile:
        r = requests.post(
            "https://api.profiler.firefox.com/compressed-store",
            headers={
                "Accept": "application/vnd.firefox-profiler+json;version=1.0",
            },
            data=infile,
        )
        r.raise_for_status()

        token = r.text

    profile_token = handle_input_line(token)
    return f"https://profiler.firefox.com/public/{profile_token}"


# Execute it only when run directly
if __name__ == "__main__":
    import sys

    for file_path in sys.argv[1:]:
        file_path = Path(file_path)
        url = upload_profile(file_path)
        print(f"Hosted at: {url}")
