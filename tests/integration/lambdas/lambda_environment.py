import os


def handler(event, context):
    '''
    '''
    return {'Hello': os.environ.get('Hello')}
