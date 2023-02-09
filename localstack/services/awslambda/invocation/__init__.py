from localstack.aws.api.lambda_ import ServiceException


class AccessDeniedException(ServiceException):
    code: str = "AccessDeniedException"
    sender_fault: bool = True
    status_code: int = 403
