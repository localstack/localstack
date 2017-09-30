import os


def handler(event, context):
    """ Simple Lambda function that returns the value of the "Hello" environment variable """
    return {'Hello': os.environ.get('Hello')}
