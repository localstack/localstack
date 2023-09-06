import copy
import datetime
import json
from typing import Optional

from localstack.aws.api import RequestContext
from localstack.aws.api.stepfunctions import (
    Arn,
    ConflictException,
    CreateStateMachineInput,
    CreateStateMachineOutput,
    Definition,
    DeleteStateMachineOutput,
    DeleteStateMachineVersionOutput,
    DescribeExecutionOutput,
    DescribeStateMachineForExecutionOutput,
    DescribeStateMachineOutput,
    ExecutionDoesNotExist,
    ExecutionList,
    ExecutionStatus,
    GetExecutionHistoryOutput,
    IncludeExecutionDataGetExecutionHistory,
    InvalidArn,
    InvalidDefinition,
    InvalidExecutionInput,
    InvalidName,
    InvalidToken,
    ListExecutionsOutput,
    ListExecutionsPageToken,
    ListStateMachinesOutput,
    ListStateMachineVersionsOutput,
    ListTagsForResourceOutput,
    LoggingConfiguration,
    LongArn,
    MissingRequiredParameter,
    Name,
    PageSize,
    PageToken,
    Publish,
    PublishStateMachineVersionOutput,
    ResourceNotFound,
    ReverseOrder,
    RevisionId,
    SendTaskFailureOutput,
    SendTaskHeartbeatOutput,
    SendTaskSuccessOutput,
    SensitiveCause,
    SensitiveData,
    SensitiveError,
    StartExecutionOutput,
    StateMachineAlreadyExists,
    StateMachineDoesNotExist,
    StateMachineList,
    StateMachineType,
    StepfunctionsApi,
    StopExecutionOutput,
    TagKeyList,
    TagList,
    TagResourceOutput,
    TaskDoesNotExist,
    TaskTimedOut,
    TaskToken,
    TraceHeader,
    TracingConfiguration,
    UntagResourceOutput,
    UpdateStateMachineOutput,
    ValidationException,
    VersionDescription,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import (
    CallbackConsumerTimeout,
    CallbackNotifyConsumerError,
    CallbackOutcomeFailure,
    CallbackOutcomeSuccess,
)
from localstack.services.stepfunctions.asl.parse.asl_parser import AmazonStateLanguageParser
from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import (
    StateMachineInstance,
    StateMachineRevision,
    StateMachineVersion,
)
from localstack.services.stepfunctions.backend.store import SFNStore, sfn_stores
from localstack.utils.aws.arns import ArnData, parse_arn
from localstack.utils.aws.arns import state_machine_arn as aws_stack_state_machine_arn
from localstack.utils.strings import long_uid


class StepFunctionsProvider(StepfunctionsApi):
    @staticmethod
    def get_store(context: RequestContext) -> SFNStore:
        return sfn_stores[context.account_id][context.region]

    def _get_execution(self, context: RequestContext, execution_arn: Arn) -> Execution:
        execution: Optional[Execution] = self.get_store(context).executions.get(execution_arn)
        if not execution:
            raise InvalidName()  # TODO
        return execution

    def _get_executions(
        self, context: RequestContext, execution_status: Optional[ExecutionStatus] = None
    ):
        store = self.get_store(context)
        execution: list[Execution] = list(store.executions.values())
        if execution_status:
            execution = list(
                filter(lambda e: e.exec_status == execution_status, store.executions.values())
            )
        return execution

    def _idempotent_revision(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> Optional[StateMachineRevision]:
        # CreateStateMachine's idempotency check is based on the state machine name, definition, type,
        # LoggingConfiguration and TracingConfiguration.
        # If a following request has a different roleArn or tags, Step Functions will ignore these differences and
        # treat it as an idempotent request of the previous. In this case, roleArn and tags will not be updated, even
        # if they are different.
        state_machines: list[StateMachineInstance] = list(
            self.get_store(context).state_machines.values()
        )
        revisions = filter(
            lambda state_machine: isinstance(state_machine, StateMachineRevision), state_machines
        )
        for state_machine in revisions:
            check = all(
                [
                    state_machine.name == request["name"],
                    state_machine.definition == request["definition"],
                    state_machine.sm_type == request.get("type") or StateMachineType.STANDARD,
                    state_machine.logging_config == request.get("loggingConfiguration"),
                    state_machine.tracing_config == request.get("tracingConfiguration"),
                ]
            )
            if check:
                return state_machine
        return None

    def _revision_by_name(
        self, context: RequestContext, name: str
    ) -> Optional[StateMachineInstance]:
        state_machines: list[StateMachineInstance] = list(
            self.get_store(context).state_machines.values()
        )
        for state_machine in state_machines:
            if isinstance(state_machine, StateMachineRevision) and state_machine.name == name:
                return state_machine
        return None

    @staticmethod
    def _validate_definition(definition: str):
        # Validate
        # TODO: pass through static analyser.
        try:
            AmazonStateLanguageParser.parse(definition)
        except Exception as ex:
            # TODO: add message from static analyser, this just helps the user debug issues in the derivation.
            raise InvalidDefinition(f"Error '{str(ex)}' in definition '{definition}'.")

    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> CreateStateMachineOutput:
        if not request.get("publish", False) and request.get("versionDescription"):
            raise ValidationException("Version description can only be set when publish is true")

        # CreateStateMachine is an idempotent API. Subsequent requests won’t create a duplicate resource if it was
        # already created.
        idem_state_machine: Optional[StateMachineRevision] = self._idempotent_revision(
            context=context, request=request
        )
        if idem_state_machine is not None:
            return CreateStateMachineOutput(
                stateMachineArn=idem_state_machine.arn, creationDate=idem_state_machine.create_date
            )

        state_machine_with_name: Optional[StateMachineRevision] = self._revision_by_name(
            context=context, name=request["name"]
        )
        if state_machine_with_name is not None:
            raise StateMachineAlreadyExists(
                f"State Machine Already Exists: '{state_machine_with_name.arn}'"
            )

        state_machine_definition: str = request["definition"]
        StepFunctionsProvider._validate_definition(definition=state_machine_definition)

        name: Optional[Name] = request["name"]
        arn = aws_stack_state_machine_arn(
            name=name, account_id=context.account_id, region_name=context.region
        )

        state_machines = self.get_store(context).state_machines

        if not name and arn in state_machines:
            raise InvalidName()

        state_machine = StateMachineRevision(
            name=name,
            arn=arn,
            role_arn=request["roleArn"],
            definition=request["definition"],
            sm_type=request.get("type"),
            logging_config=request.get("loggingConfiguration"),
            tags=request.get("tags"),
            tracing_config=request.get("tracingConfiguration"),
        )

        tags = request.get("tags")
        if tags:
            state_machine.tag_manager.add_all(tags)

        state_machines[arn] = state_machine

        create_output = CreateStateMachineOutput(
            stateMachineArn=state_machine.arn, creationDate=state_machine.create_date
        )

        if request.get("publish", False):
            version_description = request.get("versionDescription")
            state_machine_version = state_machine.create_version(description=version_description)
            if state_machine_version is not None:
                state_machine_version_arn = state_machine_version.arn
                state_machines[state_machine_version_arn] = state_machine_version
                create_output["stateMachineVersionArn"] = state_machine_version_arn

        return create_output

    def describe_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DescribeStateMachineOutput:
        # TODO: add arn validation.
        state_machine = self.get_store(context).state_machines.get(state_machine_arn)
        if state_machine is None:
            raise ExecutionDoesNotExist()
        return state_machine.describe()

    def describe_state_machine_for_execution(
        self, context: RequestContext, execution_arn: Arn
    ) -> DescribeStateMachineForExecutionOutput:
        # TODO: add arn validation.
        execution: Optional[Execution] = self.get_store(context).executions.get(execution_arn)
        if not execution:
            raise ExecutionDoesNotExist()
        return execution.to_describe_state_machine_for_execution_output()

    def send_task_heartbeat(
        self, context: RequestContext, task_token: TaskToken
    ) -> SendTaskHeartbeatOutput:
        running_executions: list[Execution] = self._get_executions(context, ExecutionStatus.RUNNING)
        for execution in running_executions:
            try:
                if execution.exec_worker.env.callback_pool_manager.heartbeat(
                    callback_id=task_token
                ):
                    return SendTaskHeartbeatOutput()
            except CallbackNotifyConsumerError as consumer_error:
                if isinstance(consumer_error, CallbackConsumerTimeout):
                    raise TaskTimedOut()
                else:
                    raise TaskDoesNotExist()
        raise InvalidToken()

    def send_task_success(
        self, context: RequestContext, task_token: TaskToken, output: SensitiveData
    ) -> SendTaskSuccessOutput:
        outcome = CallbackOutcomeSuccess(callback_id=task_token, output=output)
        running_executions: list[Execution] = self._get_executions(context, ExecutionStatus.RUNNING)
        for execution in running_executions:
            try:
                if execution.exec_worker.env.callback_pool_manager.notify(
                    callback_id=task_token, outcome=outcome
                ):
                    return SendTaskSuccessOutput()
            except CallbackNotifyConsumerError as consumer_error:
                if isinstance(consumer_error, CallbackConsumerTimeout):
                    raise TaskTimedOut()
                else:
                    raise TaskDoesNotExist()
        raise InvalidToken()

    def send_task_failure(
        self,
        context: RequestContext,
        task_token: TaskToken,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
    ) -> SendTaskFailureOutput:
        outcome = CallbackOutcomeFailure(callback_id=task_token, error=error, cause=cause)
        store = self.get_store(context)
        for execution in store.executions.values():
            try:
                if execution.exec_worker.env.callback_pool_manager.notify(
                    callback_id=task_token, outcome=outcome
                ):
                    return SendTaskFailureOutput()
            except CallbackNotifyConsumerError as consumer_error:
                if isinstance(consumer_error, CallbackConsumerTimeout):
                    raise TaskTimedOut()
                else:
                    raise TaskDoesNotExist()
        raise InvalidToken()

    def start_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name = None,
        input: SensitiveData = None,
        trace_header: TraceHeader = None,
    ) -> StartExecutionOutput:
        state_machine: Optional[StateMachineInstance] = self.get_store(context).state_machines.get(
            state_machine_arn
        )
        if not state_machine:
            raise StateMachineDoesNotExist(f"State Machine Does Not Exist: '{state_machine_arn}'")

        # Update event change parameters about the state machine and should not affect those about this execution.
        state_machine_clone = copy.deepcopy(state_machine)

        if input is None:
            input_data = dict()
        else:
            try:
                input_data = json.loads(input)
            except Exception as ex:
                raise InvalidExecutionInput(str(ex))  # TODO: report parsing error like AWS.

        normalised_state_machine_arn = (
            state_machine.source_arn
            if isinstance(state_machine, StateMachineVersion)
            else state_machine.arn
        )
        exec_name = name or long_uid()  # TODO: validate name format
        arn_data: ArnData = parse_arn(normalised_state_machine_arn)
        exec_arn = ":".join(
            [
                "arn",
                arn_data["partition"],
                arn_data["service"],
                arn_data["region"],
                arn_data["account"],
                "execution",
                "".join(arn_data["resource"].split(":")[1:]),
                exec_name,
            ]
        )
        if exec_arn in self.get_store(context).executions:
            raise InvalidName()  # TODO

        execution = Execution(
            name=exec_name,
            role_arn=state_machine_clone.role_arn,
            exec_arn=exec_arn,
            state_machine=state_machine_clone,
            start_date=datetime.datetime.now(),
            input_data=input_data,
            trace_header=trace_header,
        )
        self.get_store(context).executions[exec_arn] = execution

        execution.start()
        return execution.to_start_output()

    def describe_execution(
        self, context: RequestContext, execution_arn: Arn
    ) -> DescribeExecutionOutput:
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        return execution.to_describe_output()

    def list_executions(
        self,
        context: RequestContext,
        state_machine_arn: Arn = None,
        status_filter: ExecutionStatus = None,
        max_results: PageSize = None,
        next_token: ListExecutionsPageToken = None,
        map_run_arn: LongArn = None,
    ) -> ListExecutionsOutput:
        # TODO: add support for paging and filtering.
        executions: ExecutionList = [
            execution.to_execution_list_item()
            for execution in self.get_store(context).executions.values()
            if execution.state_machine.arn == state_machine_arn
        ]
        return ListExecutionsOutput(executions=executions)

    def list_state_machines(
        self, context: RequestContext, max_results: PageSize = None, next_token: PageToken = None
    ) -> ListStateMachinesOutput:
        # TODO: add paging support.
        state_machines: StateMachineList = [
            sm.itemise()
            for sm in self.get_store(context).state_machines.values()
            if isinstance(sm, StateMachineRevision)
        ]
        state_machines.sort(key=lambda item: item["creationDate"])
        return ListStateMachinesOutput(stateMachines=state_machines)

    def list_state_machine_versions(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        next_token: PageToken = None,
        max_results: PageSize = None,
    ) -> ListStateMachineVersionsOutput:
        # TODO: add paging support.
        state_machines = self.get_store(context).state_machines
        state_machine_revision = state_machines.get(state_machine_arn)
        if not isinstance(state_machine_revision, StateMachineRevision):
            raise InvalidArn()

        state_machine_version_items = list()
        for version_arn in state_machine_revision.versions.values():
            state_machine_version = state_machines[version_arn]
            if isinstance(state_machine_version, StateMachineVersion):
                state_machine_version_items.append(state_machine_version.itemise())
            else:
                raise RuntimeError(
                    f"Expected {version_arn} to be a StateMachine Version, but gott '{type(state_machine_version)}'."
                )

        state_machine_version_items.sort(key=lambda item: item["creationDate"], reverse=True)
        return ListStateMachineVersionsOutput(stateMachineVersions=state_machine_version_items)

    def get_execution_history(
        self,
        context: RequestContext,
        execution_arn: Arn,
        max_results: PageSize = None,
        reverse_order: ReverseOrder = None,
        next_token: PageToken = None,
        include_execution_data: IncludeExecutionDataGetExecutionHistory = None,
    ) -> GetExecutionHistoryOutput:
        # TODO: add support for paging, ordering, and other manipulations.
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        history: GetExecutionHistoryOutput = execution.to_history_output()
        return history

    def delete_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DeleteStateMachineOutput:
        # TODO: halt executions?
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(state_machine_arn)
        if isinstance(state_machine, StateMachineRevision):
            state_machines.pop(state_machine_arn)
            for version_arn in state_machine.versions.values():
                state_machines.pop(version_arn, None)
        return DeleteStateMachineOutput()

    def delete_state_machine_version(
        self, context: RequestContext, state_machine_version_arn: LongArn
    ) -> DeleteStateMachineVersionOutput:
        state_machines = self.get_store(context).state_machines
        state_machine_version = state_machines.get(state_machine_version_arn)
        if isinstance(state_machine_version, StateMachineVersion):
            state_machines.pop(state_machine_version.arn)
            state_machine_revision = state_machines.get(state_machine_version.source_arn)
            if isinstance(state_machine_revision, StateMachineRevision):
                state_machine_revision.delete_version(state_machine_version_arn)

        return DeleteStateMachineVersionOutput()

    def stop_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
    ) -> StopExecutionOutput:
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        stop_date = datetime.datetime.now()
        execution.stop(stop_date=stop_date, cause=cause, error=error)
        return StopExecutionOutput(stopDate=stop_date)

    def update_state_machine(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        definition: Definition = None,
        role_arn: Arn = None,
        logging_configuration: LoggingConfiguration = None,
        tracing_configuration: TracingConfiguration = None,
        publish: Publish = None,
        version_description: VersionDescription = None,
    ) -> UpdateStateMachineOutput:
        state_machines = self.get_store(context).state_machines

        state_machine = state_machines.get(state_machine_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise StateMachineDoesNotExist(f"State Machine Does Not Exist: '{state_machine_arn}'")

        if not any([definition, role_arn, logging_configuration]):
            raise MissingRequiredParameter(
                "Either the definition, the role ARN, the LoggingConfiguration, or the TracingConfiguration must be specified"
            )

        if definition is not None:
            self._validate_definition(definition=definition)

        revision_id = state_machine.create_revision(definition=definition, role_arn=role_arn)

        version_arn = None
        if publish:
            version = state_machine.create_version(description=version_description)
            if version is not None:
                version_arn = version.arn
                state_machines[version_arn] = version
            else:
                target_revision_id = revision_id or state_machine.revision_id
                version_arn = state_machine.versions[target_revision_id]

        update_output = UpdateStateMachineOutput(updateDate=datetime.datetime.now())
        if revision_id is not None:
            update_output["revisionId"] = revision_id
        if version_arn is not None:
            update_output["stateMachineVersionArn"] = version_arn
        return update_output

    def publish_state_machine_version(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        revision_id: RevisionId = None,
        description: VersionDescription = None,
    ) -> PublishStateMachineVersionOutput:
        state_machines = self.get_store(context).state_machines

        state_machine_revision = state_machines.get(state_machine_arn)
        if not isinstance(state_machine_revision, StateMachineRevision):
            raise InvalidArn()

        if revision_id is not None and state_machine_revision.revision_id != revision_id:
            raise ConflictException(
                f"Failed to publish the State Machine version for revision {revision_id}. "
                f"The current State Machine revision is {state_machine_revision.revision_id}."
            )

        state_machine_version = state_machine_revision.create_version(description=description)
        if state_machine_version is not None:
            state_machines[state_machine_version.arn] = state_machine_version
        else:
            target_revision_id = revision_id or state_machine_revision.revision_id
            state_machine_version_arn = state_machine_revision.versions.get(target_revision_id)
            state_machine_version = state_machines[state_machine_version_arn]

        return PublishStateMachineVersionOutput(
            creationDate=state_machine_version.create_date,
            stateMachineVersionArn=state_machine_version.arn,
        )

    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList
    ) -> TagResourceOutput:
        # TODO: add tagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        state_machine.tag_manager.add_all(tags)
        return TagResourceOutput()

    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        # TODO: add untagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        state_machine.tag_manager.remove_all(tag_keys)
        return UntagResourceOutput()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn
    ) -> ListTagsForResourceOutput:
        # TODO: add untagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        tags: TagList = state_machine.tag_manager.to_tag_list()
        return ListTagsForResourceOutput(tags=tags)
