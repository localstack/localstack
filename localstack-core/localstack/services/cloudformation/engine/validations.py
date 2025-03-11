"""
Provide validations for use within the CFn engine
"""

from localstack.aws.api import CommonServiceException


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message, sender_fault=True)
