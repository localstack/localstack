"""

There are a few well-defined ways to control this function:

1. event echo response (default)
2. blocking wait mode
3. fail mode
4. forwarding to SNS


Do not use this function outside of Lambda Destination/EventInvokeConfig tests.
"""

import json


def handler(event, context):

    # Just print the event that was passed to the Lambda
    print(json.dumps(event))
    return {"message": "Hello from Lambda"}
