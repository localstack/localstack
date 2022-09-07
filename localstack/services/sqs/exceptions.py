from localstack.aws.api import CommonServiceException


class InvalidParameterValue(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidParameterValue", message, 400, True)


class InvalidAttributeValue(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidAttributeValue", message, 400, True)


class MissingParameter(CommonServiceException):
    def __init__(self, message):
        super().__init__("MissingParameter", message, 400, True)
