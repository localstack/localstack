class CustomException(Exception):
    pass


def handler(event, context):
    raise CustomException("some error occurred")
