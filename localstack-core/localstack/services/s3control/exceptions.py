from localstack.aws.api import CommonServiceException


class NoSuchResource(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("NoSuchResource", status_code=404, message=message)
