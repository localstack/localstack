import os


def handler(event, context):
    """ Simple Lambda function that returns the value of the "Hello" environment variable """
    raw_string = os.environ.get('raw_string_result')
    if raw_string:
        return raw_string
    if event.get('map'):
        return {'Hello': event.get('map')}
    return {'Hello': os.environ.get('Hello', '_value_missing_')}
