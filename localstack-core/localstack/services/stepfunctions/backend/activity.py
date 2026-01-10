import datetime
from typing import Final

from localstack.aws.api.stepfunctions import (
    ActivityListItem,
    Arn,
    DescribeActivityOutput,
    Name,
    Timestamp,
)


class ActivityTask:
    task_input: Final[str]
    task_token: Final[str]

    def __init__(self, task_token: str, task_input: str):
        self.task_token = task_token
        self.task_input = task_input


class Activity:
    arn: Final[Arn]
    name: Final[Name]
    creation_date: Final[Timestamp]
    _tasks: Final[list[ActivityTask]]

    def __init__(self, arn: Arn, name: Name, creation_date: Timestamp | None = None):
        self.arn = arn
        self.name = name
        self.creation_date = creation_date or datetime.datetime.now(tz=datetime.UTC)
        self._tasks = []

    def add_task(self, task: ActivityTask):
        self._tasks.append(task)

    def get_task(self) -> ActivityTask | None:
        # A deque would give O(1) instead of O(n), but it is less suited for disk serialization
        return self._tasks.pop(0)

    def to_describe_activity_output(self) -> DescribeActivityOutput:
        return DescribeActivityOutput(
            activityArn=self.arn, name=self.name, creationDate=self.creation_date
        )

    def to_activity_list_item(self) -> ActivityListItem:
        return ActivityListItem(
            activityArn=self.arn, name=self.name, creationDate=self.creation_date
        )
