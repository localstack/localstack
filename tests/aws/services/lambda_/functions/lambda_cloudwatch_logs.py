"""
A simple handler which does a print on the "body" key of the event passed in.
Can be used to log different payloads, to check for the correct format in cloudwatch logs
"""


def handler(event, context):
    # Just print the log line that was passed to lambda
    print(event["body"])
    return event
