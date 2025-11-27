import datetime
from collections import deque
from typing import Final

from localstack.aws.api.stepfunctions import (
    ActivityListItem,
    Arn,
    DescribeActivityOutput,
    Name,
    TagList,
    Timestamp,
)
from localstack.services.stepfunctions.backend.tag_manager import TagManager


class ActivityTask:
    task_input: Final[str]
    task_token: Final[str]

    def __init__(self, task_token: str, task_input: str):
        self.task_token = task_token
        self.task_input = task_input


class Activity:
    """
    Represents a Step Functions activity with tag support.

    Activities are used for manual task execution in Step Functions workflows.
    This class now includes a TagManager to support full tagging operations.
    """
    arn: Final[Arn]
    name: Final[Name]
    creation_date: Final[Timestamp]
    _tasks: Final[deque[ActivityTask]]
    tag_manager: Final[TagManager]  # Tag manager for activity tagging operations

    def __init__(self, arn: Arn, name: Name, tags: TagList | None = None, creation_date: Timestamp | None = None):
        """
        Initialize a new Activity.

        :param arn: The ARN of the activity
        :param name: The name of the activity
        :param tags: Optional list of tags to apply to the activity
        :param creation_date: Optional creation date (defaults to current time)
        """
        self.arn = arn
        self.name = name
        self.creation_date = creation_date or datetime.datetime.now(tz=datetime.UTC)
        self._tasks = deque()
        # Initialize tag manager and apply any initial tags
        self.tag_manager = TagManager()
        if tags:
            self.tag_manager.add_all(tags)

    def add_task(self, task: ActivityTask):
        self._tasks.append(task)

    def get_task(self) -> ActivityTask | None:
        return self._tasks.popleft()

    def to_describe_activity_output(self) -> DescribeActivityOutput:
        return DescribeActivityOutput(
            activityArn=self.arn, name=self.name, creationDate=self.creation_date
        )

    def to_activity_list_item(self) -> ActivityListItem:
        return ActivityListItem(
            activityArn=self.arn, name=self.name, creationDate=self.creation_date
        )
