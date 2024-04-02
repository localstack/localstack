from localstack.aws.api.events import (
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
)


class Rule:
    def __init__(
        self,
        name: RuleName,
        state: RuleState = RuleState.ENABLED,
        description: RuleDescription | None = None,
        role_arn: RoleArn = None,
    ):
        self.name = name
        self.state = state
        self.description = description
        self.role_arn = role_arn

    def enable(self):
        self.state = RuleState.ENABLED

    def disable(self):
        self.state = RuleState.DISABLED


RuleDict = dict[str, Rule]
