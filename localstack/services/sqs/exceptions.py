from localstack.aws.api import CommonServiceException


class InvalidParameterValueException(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidParameterValueException", message, 400, True)


class InvalidAttributeValue(CommonServiceException):
    def __init__(self, message):
        super().__init__("InvalidAttributeValue", message, 400, True)


class MissingRequiredParameterException(CommonServiceException):
    def __init__(self, message):
        super().__init__("MissingRequiredParameterException", message, 400, True)
