# simple test function that uses python 3 features (e.g., f-strings)
# see https://github.com/localstack/localstack/issues/264


def handler(event, context):
    # the following line is Python 3 specific
    msg = f'Successfully processed {event}'
    return event
