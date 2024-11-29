class CustomException(Exception):
    message: str

    def __init__(self):
        self.message = "CustomException message"


def handler(event, context):
    raise CustomException()
