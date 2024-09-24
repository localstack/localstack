"""
Raises an exception with a message containing part of the invoke payload.

Example invoke payload:

{
    "error_msg": "test123"
}
"""

import json


def handler(event, ctx):
    print(json.dumps(event))
    raise Exception(f"Failed: {event.get('error_msg')}")
