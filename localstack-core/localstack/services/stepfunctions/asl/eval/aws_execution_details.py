from typing import Final


class AWSExecutionDetails:
    account: Final[str]
    region: Final[str]
    role_arn: Final[str]

    def __init__(self, account: str, region: str, role_arn: str):
        self.account = account
        self.region = region
        self.role_arn = role_arn
