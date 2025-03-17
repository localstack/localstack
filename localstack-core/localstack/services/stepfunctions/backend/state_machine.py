from __future__ import annotations

import abc
import datetime
import json
from collections import OrderedDict
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    Definition,
    DescribeStateMachineOutput,
    LoggingConfiguration,
    Name,
    RevisionId,
    StateMachineListItem,
    StateMachineStatus,
    StateMachineType,
    StateMachineVersionListItem,
    Tag,
    TagKeyList,
    TagList,
    TracingConfiguration,
    ValidationException,
    VariableReferences,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingConfiguration,
)
from localstack.services.stepfunctions.asl.static_analyser.variable_references_static_analyser import (
    VariableReferencesStaticAnalyser,
)
from localstack.services.stepfunctions.backend.alias import Alias
from localstack.utils.strings import long_uid


class StateMachineInstance:
    name: Name
    arn: Arn
    revision_id: Optional[RevisionId]
    definition: Definition
    role_arn: Arn
    create_date: datetime.datetime
    sm_type: StateMachineType
    logging_config: LoggingConfiguration
    cloud_watch_logging_configuration: Optional[CloudWatchLoggingConfiguration]
    tags: Optional[TagList]
    tracing_config: Optional[TracingConfiguration]

    def __init__(
        self,
        name: Name,
        arn: Arn,
        definition: Definition,
        role_arn: Arn,
        logging_config: LoggingConfiguration,
        cloud_watch_logging_configuration: Optional[CloudWatchLoggingConfiguration] = None,
        create_date: Optional[datetime.datetime] = None,
        sm_type: Optional[StateMachineType] = None,
        tags: Optional[TagList] = None,
        tracing_config: Optional[TracingConfiguration] = None,
    ):
        self.name = name
        self.arn = arn
        self.revision_id = None
        self.definition = definition
        self.role_arn = role_arn
        self.create_date = create_date or datetime.datetime.now(tz=datetime.timezone.utc)
        self.sm_type = sm_type or StateMachineType.STANDARD
        self.logging_config = logging_config
        self.cloud_watch_logging_configuration = cloud_watch_logging_configuration
        self.tags = tags
        self.tracing_config = tracing_config

    def describe(self) -> DescribeStateMachineOutput:
        describe_output = DescribeStateMachineOutput(
            stateMachineArn=self.arn,
            name=self.name,
            status=StateMachineStatus.ACTIVE,
            definition=self.definition,
            roleArn=self.role_arn,
            type=self.sm_type,
            creationDate=self.create_date,
            loggingConfiguration=self.logging_config,
        )

        if self.revision_id:
            describe_output["revisionId"] = self.revision_id

        variable_references: VariableReferences = VariableReferencesStaticAnalyser.process_and_get(
            definition=self.definition
        )
        if variable_references:
            describe_output["variableReferences"] = variable_references

        return describe_output

    @abc.abstractmethod
    def itemise(self): ...


class TestStateMachine(StateMachineInstance):
    def __init__(
        self,
        name: Name,
        arn: Arn,
        definition: Definition,
        role_arn: Arn,
        create_date: Optional[datetime.datetime] = None,
    ):
        super().__init__(
            name,
            arn,
            definition,
            role_arn,
            create_date,
            StateMachineType.STANDARD,
            None,
            None,
            None,
        )

    def itemise(self):
        raise NotImplementedError("TestStateMachine does not support itemise.")


class TagManager:
    _tags: Final[dict[str, Optional[str]]]

    def __init__(self):
        self._tags = OrderedDict()

    @staticmethod
    def _validate_key_value(key: str) -> None:
        if not key:
            raise ValidationException()

    @staticmethod
    def _validate_tag_value(value: str) -> None:
        if value is None:
            raise ValidationException()

    def add_all(self, tags: TagList) -> None:
        for tag in tags:
            tag_key = tag["key"]
            tag_value = tag["value"]
            self._validate_key_value(key=tag_key)
            self._validate_tag_value(value=tag_value)
            self._tags[tag_key] = tag_value

    def remove_all(self, keys: TagKeyList):
        for key in keys:
            self._validate_key_value(key=key)
            self._tags.pop(key, None)

    def to_tag_list(self) -> TagList:
        tag_list = list()
        for key, value in self._tags.items():
            tag_list.append(Tag(key=key, value=value))
        return tag_list


class StateMachineRevision(StateMachineInstance):
    _next_version_number: int
    versions: Final[dict[RevisionId, Arn]]
    tag_manager: Final[TagManager]
    aliases: Final[set[Alias]]

    def __init__(
        self,
        name: Name,
        arn: Arn,
        definition: Definition,
        role_arn: Arn,
        logging_config: LoggingConfiguration,
        cloud_watch_logging_configuration: Optional[CloudWatchLoggingConfiguration],
        create_date: Optional[datetime.datetime] = None,
        sm_type: Optional[StateMachineType] = None,
        tags: Optional[TagList] = None,
        tracing_config: Optional[TracingConfiguration] = None,
    ):
        super().__init__(
            name,
            arn,
            definition,
            role_arn,
            logging_config,
            cloud_watch_logging_configuration,
            create_date,
            sm_type,
            tags,
            tracing_config,
        )
        self.versions = dict()
        self._version_number = 0
        self.tag_manager = TagManager()
        if tags:
            self.tag_manager.add_all(tags)
        self.aliases = set()

    def create_revision(
        self,
        definition: Optional[str],
        role_arn: Optional[Arn],
        logging_configuration: Optional[LoggingConfiguration],
    ) -> Optional[RevisionId]:
        update_definition = definition and json.loads(definition) != json.loads(self.definition)
        if update_definition:
            self.definition = definition

        update_role_arn = role_arn and role_arn != self.role_arn
        if update_role_arn:
            self.role_arn = role_arn

        update_logging_configuration = (
            logging_configuration and logging_configuration != self.logging_config
        )
        if update_logging_configuration:
            self.logging_config = logging_configuration
            self.cloud_watch_logging_configuration = (
                CloudWatchLoggingConfiguration.from_logging_configuration(
                    state_machine_arn=self.arn, logging_configuration=self.logging_config
                )
            )

        if any([update_definition, update_role_arn, update_logging_configuration]):
            self.revision_id = long_uid()

        return self.revision_id

    def create_version(self, description: Optional[str]) -> Optional[StateMachineVersion]:
        if self.revision_id not in self.versions:
            self._version_number += 1
            version = StateMachineVersion(
                self, version=self._version_number, description=description
            )
            self.versions[self.revision_id] = version.arn

            return version
        return None

    def delete_version(self, state_machine_version_arn: Arn) -> None:
        source_revision_id = None
        for revision_id, version_arn in self.versions.items():
            if version_arn == state_machine_version_arn:
                source_revision_id = revision_id
                break
        self.versions.pop(source_revision_id, None)

    def itemise(self) -> StateMachineListItem:
        return StateMachineListItem(
            stateMachineArn=self.arn,
            name=self.name,
            type=self.sm_type,
            creationDate=self.create_date,
        )


class StateMachineVersion(StateMachineInstance):
    source_arn: Arn
    version: int
    description: Optional[str]

    def __init__(
        self, state_machine_revision: StateMachineRevision, version: int, description: Optional[str]
    ):
        version_arn = f"{state_machine_revision.arn}:{version}"
        super().__init__(
            name=state_machine_revision.name,
            arn=version_arn,
            definition=state_machine_revision.definition,
            role_arn=state_machine_revision.role_arn,
            create_date=datetime.datetime.now(tz=datetime.timezone.utc),
            sm_type=state_machine_revision.sm_type,
            logging_config=state_machine_revision.logging_config,
            cloud_watch_logging_configuration=state_machine_revision.cloud_watch_logging_configuration,
            tags=state_machine_revision.tags,
            tracing_config=state_machine_revision.tracing_config,
        )
        self.source_arn = state_machine_revision.arn
        self.revision_id = state_machine_revision.revision_id
        self.version = version
        self.description = description

    def describe(self) -> DescribeStateMachineOutput:
        describe_output: DescribeStateMachineOutput = super().describe()
        if self.description:
            describe_output["description"] = self.description
        return describe_output

    def itemise(self) -> StateMachineVersionListItem:
        return StateMachineVersionListItem(
            stateMachineVersionArn=self.arn, creationDate=self.create_date
        )
