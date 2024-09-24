from localstack.aws.api import CommonServiceException


class MalformedXML(CommonServiceException):
    def __init__(self, message=None):
        if not message:
            message = "The XML you provided was not well-formed or did not validate against our published schema"
        super().__init__("MalformedXML", status_code=400, message=message)


class MalformedACLError(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedACLError", status_code=400, message=message)


class InvalidRequest(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidRequest", status_code=400, message=message)


class UnexpectedContent(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("UnexpectedContent", status_code=400, message=message)


class NoSuchConfiguration(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("NoSuchConfiguration", status_code=404, message=message)


class InvalidBucketState(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidBucketState", status_code=409, message=message)


class NoSuchObjectLockConfiguration(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("NoSuchObjectLockConfiguration", status_code=404, message=message)


class MalformedPolicy(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("MalformedPolicy", status_code=400, message=message)
