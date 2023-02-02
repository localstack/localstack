from localstack.aws.api import CommonServiceException


class InternalError(CommonServiceException):
    def __init__(self, message):
        super(InternalError, self).__init__(
            code="InternalError",
            message=message,
        )


class IncorrectInstanceStateError(CommonServiceException):
    def __init__(self, instance_id):
        super(IncorrectInstanceStateError, self).__init__(
            code="IncorrectInstanceState",
            message=f"The instance '{instance_id}' is not in a state from which it can be started",
        )


class InvalidAMIIdError(CommonServiceException):
    def __init__(self, ami_id):
        super(InvalidAMIIdError, self).__init__(
            code="InvalidAMIID.NotFound", message=f"The image id '{ami_id}' does not exist"
        )


class InvalidInstanceIdError(CommonServiceException):
    def __init__(self, instance_id):
        super(InvalidInstanceIdError, self).__init__(
            code="InvalidInstanceID.NotFound",
            message=f"The instance ID '{instance_id}' does not exist",
        )


class MissingParameterError(CommonServiceException):
    def __init__(self, parameter):
        super(MissingParameterError, self).__init__(
            code="MissingParameter",
            message=f"The request must contain the parameter {parameter}",
        )

class InvalidLaunchTemplateNameError(CommonServiceException):
    def __int__(self):
        super(InvalidLaunchTemplateNameError, self).__init__(
            code="InvalidLaunchTemplateName.MalformedException",
            message = "A launch template name must be between 3 and 128 characters, and may contain letters, numbers, and the following characters: - ( ) . / _.'",
        )