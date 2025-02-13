from localstack.aws.api import CommonServiceException


class ValidationException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationException", message, 400, True)


class AccessDeniedException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("AccessDeniedException", message, 400, True)


class TagException(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("TagException", status_code=400, message=message)
