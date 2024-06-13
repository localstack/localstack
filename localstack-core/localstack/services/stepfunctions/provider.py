import copy
import datetime
import json
import logging
import re
import time
from typing import Final, Optional

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.stepfunctions import (
    ActivityDoesNotExist,
    Arn,
    ConflictException,
    CreateActivityOutput,
    CreateStateMachineInput,
    CreateStateMachineOutput,
    Definition,
    DeleteActivityOutput,
    DeleteStateMachineOutput,
    DeleteStateMachineVersionOutput,
    DescribeActivityOutput,
    DescribeExecutionOutput,
    DescribeMapRunOutput,
    DescribeStateMachineForExecutionOutput,
    DescribeStateMachineOutput,
    ExecutionDoesNotExist,
    ExecutionList,
    ExecutionRedriveFilter,
    ExecutionStatus,
    GetActivityTaskOutput,
    GetExecutionHistoryOutput,
    IncludeExecutionDataGetExecutionHistory,
    InspectionLevel,
    InvalidArn,
    InvalidDefinition,
    InvalidExecutionInput,
    InvalidLoggingConfiguration,
    InvalidName,
    InvalidToken,
    ListActivitiesOutput,
    ListExecutionsOutput,
    ListExecutionsPageToken,
    ListMapRunsOutput,
    ListStateMachinesOutput,
    ListStateMachineVersionsOutput,
    ListTagsForResourceOutput,
    LoggingConfiguration,
    LogLevel,
    LongArn,
    MaxConcurrency,
    MissingRequiredParameter,
    Name,
    PageSize,
    PageToken,
    Publish,
    PublishStateMachineVersionOutput,
    ResourceNotFound,
    RevealSecrets,
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
    TestStateOutput,
    ToleratedFailureCount,
    ToleratedFailurePercentage,
    TraceHeader,
    TracingConfiguration,
    UntagResourceOutput,
    UpdateMapRunOutput,
    UpdateStateMachineOutput,
    ValidationException,
    VersionDescription,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecord,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import (
    ActivityCallbackEndpoint,
    CallbackConsumerTimeout,
    CallbackNotifyConsumerError,
    CallbackOutcomeFailure,
    CallbackOutcomeSuccess,
)
from localstack.services.stepfunctions.asl.eval.event.logging import (
    CloudWatchLoggingConfiguration,
    CloudWatchLoggingSession,
)
from localstack.services.stepfunctions.asl.parse.asl_parser import (
    ASLParserException,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser
from localstack.services.stepfunctions.asl.static_analyser.test_state.test_state_analyser import (
    TestStateStaticAnalyser,
)
from localstack.services.stepfunctions.backend.activity import Activity, ActivityTask
from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import (
    StateMachineInstance,
    StateMachineRevision,
    StateMachineVersion,
    TestStateMachine,
)
from localstack.services.stepfunctions.backend.store import SFNStore, sfn_stores
from localstack.services.stepfunctions.backend.test_state.execution import TestStateExecution
from localstack.state import StateVisitor
from localstack.utils.aws.arns import (
    stepfunctions_activity_arn,
    stepfunctions_execution_state_machine_arn,
    stepfunctions_state_machine_arn,
)
from localstack.utils.strings import long_uid, short_uid

LOG = logging.getLogger(__name__)


class StepFunctionsProvider(StepfunctionsApi, ServiceLifecycleHook):
    _TEST_STATE_MAX_TIMEOUT_SECONDS: Final[int] = 300  # 5 minutes.

    @staticmethod
    def get_store(context: RequestContext) -> SFNStore:
        return sfn_stores[context.account_id][context.region]

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(sfn_stores)

    _STATE_MACHINE_ARN_REGEX: Final[re.Pattern] = re.compile(
        r"^arn:aws:states:[a-z0-9-]+:[0-9]{12}:stateMachine:[a-zA-Z0-9-_.]+(:\d+)?$"
    )

    _STATE_MACHINE_EXECUTION_ARN_REGEX: Final[re.Pattern] = re.compile(
        r"^arn:aws:states:[a-z0-9-]+:[0-9]{12}:(stateMachine|execution):[a-zA-Z0-9-_.]+(:\d+)?(:[a-zA-Z0-9-_.]+)?$"
    )

    _ACTIVITY_ARN_REGEX: Final[re.Pattern] = re.compile(
        r"^arn:aws:states:[a-z0-9-]+:[0-9]{12}:activity:[a-zA-Z0-9-_]+$"
    )

    @staticmethod
    def _validate_state_machine_arn(state_machine_arn: str) -> None:
        # TODO: InvalidArn exception message do not communicate which part of the ARN is incorrect.
        if not StepFunctionsProvider._STATE_MACHINE_ARN_REGEX.match(state_machine_arn):
            raise InvalidArn(f"Invalid arn: '{state_machine_arn}'")

    @staticmethod
    def _raise_state_machine_does_not_exist(state_machine_arn: str) -> None:
        raise StateMachineDoesNotExist(f"State Machine Does Not Exist: '{state_machine_arn}'")

    def _validate_state_machine_execution_arn(self, execution_arn: str) -> None:
        # TODO: InvalidArn exception message do not communicate which part of the ARN is incorrect.
        if not StepFunctionsProvider._STATE_MACHINE_EXECUTION_ARN_REGEX.match(execution_arn):
            raise InvalidArn(f"Invalid arn: '{execution_arn}'")

    @staticmethod
    def _validate_activity_arn(activity_arn: str) -> None:
        # TODO: InvalidArn exception message do not communicate which part of the ARN is incorrect.
        if not StepFunctionsProvider._ACTIVITY_ARN_REGEX.match(activity_arn):
            raise InvalidArn(f"Invalid arn: '{activity_arn}'")

    @staticmethod
    def _validate_activity_name(name: str) -> None:
        # The activity name is validated according to the AWS StepFunctions documentation, the name should not contain:
        # - white space
        # - brackets < > { } [ ]
        # - wildcard characters ? *
        # - special characters " # % \ ^ | ~ ` $ & , ; : /
        # - control characters (U+0000-001F, U+007F-009F)
        # https://docs.aws.amazon.com/step-functions/latest/apireference/API_CreateActivity.html#API_CreateActivity_RequestSyntax
        invalid_chars = set(' <>{}[]?*"#%\\^|~`$&,;:/')
        control_chars = {chr(i) for i in range(32)} | {chr(i) for i in range(127, 160)}
        invalid_chars |= control_chars
        for char in name:
            if char in invalid_chars:
                raise InvalidName(f"Invalid Name: '{name}'")

    def _get_execution(self, context: RequestContext, execution_arn: Arn) -> Execution:
        execution: Optional[Execution] = self.get_store(context).executions.get(execution_arn)
        if not execution:
            raise ExecutionDoesNotExist(f"Execution Does Not Exist: '{execution_arn}'")
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

    def _get_activity(self, context: RequestContext, activity_arn: Arn) -> Activity:
        maybe_activity: Optional[Activity] = self.get_store(context).activities.get(
            activity_arn, None
        )
        if maybe_activity is None:
            raise ActivityDoesNotExist(f"Activity Does Not Exist: '{activity_arn}'")
        return maybe_activity

    def _idempotent_revision(
        self,
        context: RequestContext,
        name: str,
        definition: Definition,
        state_machine_type: StateMachineType,
        logging_configuration: LoggingConfiguration,
        tracing_configuration: TracingConfiguration,
    ) -> Optional[StateMachineRevision]:
        # CreateStateMachine's idempotency check is based on the state machine name, definition, type,
        # LoggingConfiguration and TracingConfiguration.
        # If a following request has a different roleArn or tags, Step Functions will ignore these differences and
        # treat it as an idempotent request of the previous. In this case, roleArn and tags will not be updated, even
        # if they are different.
        state_machines: list[StateMachineInstance] = list(
            self.get_store(context).state_machines.values()
        )
        revisions = filter(lambda sm: isinstance(sm, StateMachineRevision), state_machines)
        for state_machine in revisions:
            check = all(
                [
                    state_machine.name == name,
                    state_machine.definition == definition,
                    state_machine.sm_type == state_machine_type,
                    state_machine.logging_config == logging_configuration,
                    state_machine.tracing_config == tracing_configuration,
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
    def _validate_definition(definition: str, static_analysers: list[StaticAnalyser]) -> None:
        try:
            for static_analyser in static_analysers:
                static_analyser.analyse(definition)
        except ASLParserException as asl_parser_exception:
            invalid_definition = InvalidDefinition()
            invalid_definition.message = repr(asl_parser_exception)
            raise invalid_definition
        except Exception as exception:
            exception_name = exception.__class__.__name__
            exception_args = list(exception.args)
            invalid_definition = InvalidDefinition()
            invalid_definition.message = (
                f"Error={exception_name} Args={exception_args} in definition '{definition}'."
            )
            raise invalid_definition

    @staticmethod
    def _sanitise_logging_configuration(logging_configuration: LoggingConfiguration) -> None:
        level = logging_configuration.get("level")
        destinations = logging_configuration.get("destinations")

        if destinations is not None and len(destinations) > 1:
            raise InvalidLoggingConfiguration(
                "Invalid Logging Configuration: Must specify exactly one Log Destination."
            )

        # A LogLevel that is not OFF, should have a destination.
        if level is not None and level != LogLevel.OFF and not destinations:
            raise InvalidLoggingConfiguration(
                "Invalid Logging Configuration: Must specify exactly one Log Destination."
            )

        # Default for level is OFF.
        level = level or LogLevel.OFF

        # Default for includeExecutionData is False.
        include_flag = logging_configuration.get("includeExecutionData", False)

        # Update configuration object.
        logging_configuration["level"] = level
        logging_configuration["includeExecutionData"] = include_flag

    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput, **kwargs
    ) -> CreateStateMachineOutput:
        if not request.get("publish", False) and request.get("versionDescription"):
            raise ValidationException("Version description can only be set when publish is true")

        # Extract parameters and set defaults.
        state_machine_name = request["name"]
        state_machine_role_arn = request["roleArn"]
        state_machine_definition = request["definition"]
        state_machine_type = request.get("type") or StateMachineType.STANDARD
        state_machine_tracing_configuration = request.get("tracingConfiguration")
        state_machine_tags = request.get("tags")
        state_machine_logging_configuration = request.get(
            "loggingConfiguration", LoggingConfiguration()
        )
        self._sanitise_logging_configuration(
            logging_configuration=state_machine_logging_configuration
        )

        # CreateStateMachine is an idempotent API. Subsequent requests won’t create a duplicate resource if it was
        # already created.
        idem_state_machine: Optional[StateMachineRevision] = self._idempotent_revision(
            context=context,
            name=state_machine_name,
            definition=state_machine_definition,
            state_machine_type=state_machine_type,
            logging_configuration=state_machine_logging_configuration,
            tracing_configuration=state_machine_tracing_configuration,
        )
        if idem_state_machine is not None:
            return CreateStateMachineOutput(
                stateMachineArn=idem_state_machine.arn, creationDate=idem_state_machine.create_date
            )

        # Assert this state machine name is unique.
        state_machine_with_name: Optional[StateMachineRevision] = self._revision_by_name(
            context=context, name=state_machine_name
        )
        if state_machine_with_name is not None:
            raise StateMachineAlreadyExists(
                f"State Machine Already Exists: '{state_machine_with_name.arn}'"
            )

        # Compute the state machine's Arn.
        state_machine_arn = stepfunctions_state_machine_arn(
            name=state_machine_name, account_id=context.account_id, region_name=context.region
        )
        state_machines = self.get_store(context).state_machines

        # Reduce the logging configuration to a usable cloud watch representation, and validate the destinations
        # if any were given.
        cloud_watch_logging_configuration = (
            CloudWatchLoggingConfiguration.from_logging_configuration(
                state_machine_arn=state_machine_arn,
                logging_configuration=state_machine_logging_configuration,
            )
        )
        if cloud_watch_logging_configuration is not None:
            cloud_watch_logging_configuration.validate()

        # Run static analysers on the definition given.
        StepFunctionsProvider._validate_definition(
            definition=state_machine_definition, static_analysers=[StaticAnalyser()]
        )

        # Create the state machine and add it to the store.
        state_machine = StateMachineRevision(
            name=state_machine_name,
            arn=state_machine_arn,
            role_arn=state_machine_role_arn,
            definition=state_machine_definition,
            sm_type=state_machine_type,
            logging_config=state_machine_logging_configuration,
            cloud_watch_logging_configuration=cloud_watch_logging_configuration,
            tracing_config=state_machine_tracing_configuration,
            tags=state_machine_tags,
        )
        state_machines[state_machine_arn] = state_machine

        create_output = CreateStateMachineOutput(
            stateMachineArn=state_machine.arn, creationDate=state_machine.create_date
        )

        # Create the first version if the 'publish' flag is used.
        if request.get("publish", False):
            version_description = request.get("versionDescription")
            state_machine_version = state_machine.create_version(description=version_description)
            if state_machine_version is not None:
                state_machine_version_arn = state_machine_version.arn
                state_machines[state_machine_version_arn] = state_machine_version
                create_output["stateMachineVersionArn"] = state_machine_version_arn

        return create_output

    def describe_state_machine(
        self, context: RequestContext, state_machine_arn: Arn, **kwargs
    ) -> DescribeStateMachineOutput:
        self._validate_state_machine_arn(state_machine_arn)
        state_machine = self.get_store(context).state_machines.get(state_machine_arn)
        if state_machine is None:
            self._raise_state_machine_does_not_exist(state_machine_arn)
        return state_machine.describe()

    def describe_state_machine_for_execution(
        self, context: RequestContext, execution_arn: Arn, **kwargs
    ) -> DescribeStateMachineForExecutionOutput:
        self._validate_state_machine_execution_arn(execution_arn)
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        return execution.to_describe_state_machine_for_execution_output()

    def send_task_heartbeat(
        self, context: RequestContext, task_token: TaskToken, **kwargs
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
        self, context: RequestContext, task_token: TaskToken, output: SensitiveData, **kwargs
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
        raise InvalidToken("Invalid token")

    def send_task_failure(
        self,
        context: RequestContext,
        task_token: TaskToken,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
        **kwargs,
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
        raise InvalidToken("Invalid token")

    def start_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name = None,
        input: SensitiveData = None,
        trace_header: TraceHeader = None,
        **kwargs,
    ) -> StartExecutionOutput:
        self._validate_state_machine_arn(state_machine_arn)
        state_machine: Optional[StateMachineInstance] = self.get_store(context).state_machines.get(
            state_machine_arn
        )
        if not state_machine:
            self._raise_state_machine_does_not_exist(state_machine_arn)

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
        exec_arn = stepfunctions_execution_state_machine_arn(
            normalised_state_machine_arn, exec_name
        )
        if exec_arn in self.get_store(context).executions:
            raise InvalidName()  # TODO

        # Create the execution logging session, if logging is configured.
        cloud_watch_logging_session = None
        if state_machine.cloud_watch_logging_configuration is not None:
            cloud_watch_logging_session = CloudWatchLoggingSession(
                execution_arn=exec_arn,
                configuration=state_machine.cloud_watch_logging_configuration,
            )

        execution = Execution(
            name=exec_name,
            role_arn=state_machine_clone.role_arn,
            exec_arn=exec_arn,
            account_id=context.account_id,
            region_name=context.region,
            state_machine=state_machine_clone,
            start_date=datetime.datetime.now(tz=datetime.timezone.utc),
            cloud_watch_logging_session=cloud_watch_logging_session,
            input_data=input_data,
            trace_header=trace_header,
            activity_store=self.get_store(context).activities,
        )
        self.get_store(context).executions[exec_arn] = execution

        execution.start()
        return execution.to_start_output()

    def describe_execution(
        self, context: RequestContext, execution_arn: Arn, **kwargs
    ) -> DescribeExecutionOutput:
        self._validate_state_machine_execution_arn(execution_arn)
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        return execution.to_describe_output()

    @staticmethod
    def _list_execution_filter(
        ex: Execution, state_machine_arn: str | None, status_filter: str | None
    ) -> bool:
        if state_machine_arn and ex.state_machine.arn != state_machine_arn:
            return False

        if not status_filter:
            return True
        return ex.exec_status == status_filter

    def list_executions(
        self,
        context: RequestContext,
        state_machine_arn: Arn = None,
        status_filter: ExecutionStatus = None,
        max_results: PageSize = None,
        next_token: ListExecutionsPageToken = None,
        map_run_arn: LongArn = None,
        redrive_filter: ExecutionRedriveFilter = None,
        **kwargs,
    ) -> ListExecutionsOutput:
        self._validate_state_machine_arn(state_machine_arn)

        state_machine = self.get_store(context).state_machines.get(state_machine_arn)
        if state_machine is None:
            self._raise_state_machine_does_not_exist(state_machine_arn)

        # TODO: add support for paging

        allowed_execution_status = [
            ExecutionStatus.SUCCEEDED,
            ExecutionStatus.TIMED_OUT,
            ExecutionStatus.PENDING_REDRIVE,
            ExecutionStatus.ABORTED,
            ExecutionStatus.FAILED,
            ExecutionStatus.RUNNING,
        ]

        validation_errors = []

        if status_filter and status_filter not in allowed_execution_status:
            validation_errors.append(
                f"Value '{status_filter}' at 'statusFilter' failed to satisfy constraint: Member must satisfy enum value set: [{', '.join(allowed_execution_status)}]"
            )

        if not state_machine_arn and not map_run_arn:
            validation_errors.append("Must provide a StateMachine ARN or MapRun ARN")

        if validation_errors:
            errors_message = "; ".join(validation_errors)
            message = f"{len(validation_errors)} validation {'errors' if len(validation_errors) > 1 else 'error'} detected: {errors_message}"
            raise CommonServiceException(message=message, code="ValidationException")

        executions: ExecutionList = [
            execution.to_execution_list_item()
            for execution in self.get_store(context).executions.values()
            if self._list_execution_filter(
                execution, state_machine_arn=state_machine_arn, status_filter=status_filter
            )
        ]
        return ListExecutionsOutput(executions=executions)

    def list_state_machines(
        self,
        context: RequestContext,
        max_results: PageSize = None,
        next_token: PageToken = None,
        **kwargs,
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
        **kwargs,
    ) -> ListStateMachineVersionsOutput:
        # TODO: add paging support.
        self._validate_state_machine_arn(state_machine_arn)

        state_machines = self.get_store(context).state_machines
        state_machine_revision = state_machines.get(state_machine_arn)
        if not isinstance(state_machine_revision, StateMachineRevision):
            raise InvalidArn(f"Invalid arn: {state_machine_arn}")

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
        **kwargs,
    ) -> GetExecutionHistoryOutput:
        # TODO: add support for paging, ordering, and other manipulations.
        self._validate_state_machine_execution_arn(execution_arn)
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        history: GetExecutionHistoryOutput = execution.to_history_output()
        if reverse_order:
            history["events"].reverse()
        return history

    def delete_state_machine(
        self, context: RequestContext, state_machine_arn: Arn, **kwargs
    ) -> DeleteStateMachineOutput:
        # TODO: halt executions?
        self._validate_state_machine_arn(state_machine_arn)
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(state_machine_arn)
        if isinstance(state_machine, StateMachineRevision):
            state_machines.pop(state_machine_arn)
            for version_arn in state_machine.versions.values():
                state_machines.pop(version_arn, None)
        return DeleteStateMachineOutput()

    def delete_state_machine_version(
        self, context: RequestContext, state_machine_version_arn: LongArn, **kwargs
    ) -> DeleteStateMachineVersionOutput:
        self._validate_state_machine_arn(state_machine_version_arn)
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
        **kwargs,
    ) -> StopExecutionOutput:
        self._validate_state_machine_execution_arn(execution_arn)
        execution: Execution = self._get_execution(context=context, execution_arn=execution_arn)
        stop_date = datetime.datetime.now(tz=datetime.timezone.utc)
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
        **kwargs,
    ) -> UpdateStateMachineOutput:
        self._validate_state_machine_arn(state_machine_arn)
        state_machines = self.get_store(context).state_machines

        state_machine = state_machines.get(state_machine_arn)
        if not isinstance(state_machine, StateMachineRevision):
            self._raise_state_machine_does_not_exist(state_machine_arn)

        if not any([definition, role_arn, logging_configuration]):
            raise MissingRequiredParameter(
                "Either the definition, the role ARN, the LoggingConfiguration, "
                "or the TracingConfiguration must be specified"
            )

        if definition is not None:
            self._validate_definition(definition=definition, static_analysers=[StaticAnalyser()])

        if logging_configuration is not None:
            self._sanitise_logging_configuration(logging_configuration=logging_configuration)

        revision_id = state_machine.create_revision(
            definition=definition, role_arn=role_arn, logging_configuration=logging_configuration
        )

        version_arn = None
        if publish:
            version = state_machine.create_version(description=version_description)
            if version is not None:
                version_arn = version.arn
                state_machines[version_arn] = version
            else:
                target_revision_id = revision_id or state_machine.revision_id
                version_arn = state_machine.versions[target_revision_id]

        update_output = UpdateStateMachineOutput(
            updateDate=datetime.datetime.now(tz=datetime.timezone.utc)
        )
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
        **kwargs,
    ) -> PublishStateMachineVersionOutput:
        self._validate_state_machine_arn(state_machine_arn)
        state_machines = self.get_store(context).state_machines

        state_machine_revision = state_machines.get(state_machine_arn)
        if not isinstance(state_machine_revision, StateMachineRevision):
            self._raise_state_machine_does_not_exist(state_machine_arn)

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
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceOutput:
        # TODO: add tagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        state_machine.tag_manager.add_all(tags)
        return TagResourceOutput()

    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceOutput:
        # TODO: add untagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        state_machine.tag_manager.remove_all(tag_keys)
        return UntagResourceOutput()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceOutput:
        # TODO: add untagging for activities.
        state_machines = self.get_store(context).state_machines
        state_machine = state_machines.get(resource_arn)
        if not isinstance(state_machine, StateMachineRevision):
            raise ResourceNotFound(f"Resource not found: '{resource_arn}'")

        tags: TagList = state_machine.tag_manager.to_tag_list()
        return ListTagsForResourceOutput(tags=tags)

    def describe_map_run(
        self, context: RequestContext, map_run_arn: LongArn, **kwargs
    ) -> DescribeMapRunOutput:
        store = self.get_store(context)
        for execution in store.executions.values():
            map_run_record: Optional[MapRunRecord] = (
                execution.exec_worker.env.map_run_record_pool_manager.get(map_run_arn)
            )
            if map_run_record is not None:
                return map_run_record.describe()
        raise ResourceNotFound()

    def list_map_runs(
        self,
        context: RequestContext,
        execution_arn: Arn,
        max_results: PageSize = None,
        next_token: PageToken = None,
        **kwargs,
    ) -> ListMapRunsOutput:
        # TODO: add support for paging.
        execution = self._get_execution(context=context, execution_arn=execution_arn)
        map_run_records: list[MapRunRecord] = (
            execution.exec_worker.env.map_run_record_pool_manager.get_all()
        )
        return ListMapRunsOutput(
            mapRuns=[map_run_record.list_item() for map_run_record in map_run_records]
        )

    def update_map_run(
        self,
        context: RequestContext,
        map_run_arn: LongArn,
        max_concurrency: MaxConcurrency = None,
        tolerated_failure_percentage: ToleratedFailurePercentage = None,
        tolerated_failure_count: ToleratedFailureCount = None,
        **kwargs,
    ) -> UpdateMapRunOutput:
        if tolerated_failure_percentage is not None or tolerated_failure_count is not None:
            raise NotImplementedError(
                "Updating of ToleratedFailureCount and ToleratedFailurePercentage is currently unsupported."
            )
        # TODO: investigate behaviour of empty requests.
        store = self.get_store(context)
        for execution in store.executions.values():
            map_run_record: Optional[MapRunRecord] = (
                execution.exec_worker.env.map_run_record_pool_manager.get(map_run_arn)
            )
            if map_run_record is not None:
                map_run_record.update(
                    max_concurrency=max_concurrency,
                    tolerated_failure_count=tolerated_failure_count,
                    tolerated_failure_percentage=tolerated_failure_percentage,
                )
                LOG.warning(
                    "StepFunctions UpdateMapRun changes are currently not being reflected in the MapRun instances."
                )
                return UpdateMapRunOutput()
        raise ResourceNotFound()

    def test_state(
        self,
        context: RequestContext,
        definition: Definition,
        role_arn: Arn,
        input: SensitiveData = None,
        inspection_level: InspectionLevel = None,
        reveal_secrets: RevealSecrets = None,
        **kwargs,
    ) -> TestStateOutput:
        StepFunctionsProvider._validate_definition(
            definition=definition, static_analysers=[TestStateStaticAnalyser()]
        )

        name: Optional[Name] = f"TestState-{short_uid()}"
        arn = stepfunctions_state_machine_arn(
            name=name, account_id=context.account_id, region_name=context.region
        )
        state_machine = TestStateMachine(
            name=name,
            arn=arn,
            role_arn=role_arn,
            definition=definition,
        )
        exec_arn = stepfunctions_execution_state_machine_arn(state_machine.arn, name)

        input_json = json.loads(input)
        execution = TestStateExecution(
            name=name,
            role_arn=role_arn,
            exec_arn=exec_arn,
            account_id=context.account_id,
            region_name=context.region,
            state_machine=state_machine,
            start_date=datetime.datetime.now(tz=datetime.timezone.utc),
            input_data=input_json,
            activity_store=self.get_store(context).activities,
        )
        execution.start()

        test_state_output = execution.to_test_state_output(
            inspection_level=inspection_level or InspectionLevel.INFO
        )

        return test_state_output

    def create_activity(
        self, context: RequestContext, name: Name, tags: TagList = None, **kwargs
    ) -> CreateActivityOutput:
        self._validate_activity_name(name=name)

        activity_arn = stepfunctions_activity_arn(
            name=name, account_id=context.account_id, region_name=context.region
        )
        activities = self.get_store(context).activities
        if activity_arn not in activities:
            activity = Activity(arn=activity_arn, name=name)
            activities[activity_arn] = activity
        else:
            activity = activities[activity_arn]

        return CreateActivityOutput(activityArn=activity.arn, creationDate=activity.creation_date)

    def delete_activity(
        self, context: RequestContext, activity_arn: Arn, **kwargs
    ) -> DeleteActivityOutput:
        self._validate_activity_arn(activity_arn)
        self.get_store(context).activities.pop(activity_arn, None)
        return DeleteActivityOutput()

    def describe_activity(
        self, context: RequestContext, activity_arn: Arn, **kwargs
    ) -> DescribeActivityOutput:
        self._validate_activity_arn(activity_arn)
        activity = self._get_activity(context=context, activity_arn=activity_arn)
        return activity.to_describe_activity_output()

    def list_activities(
        self,
        context: RequestContext,
        max_results: PageSize = None,
        next_token: PageToken = None,
        **kwargs,
    ) -> ListActivitiesOutput:
        activities: list[Activity] = list(self.get_store(context).activities.values())
        return ListActivitiesOutput(
            activities=[activity.to_activity_list_item() for activity in activities]
        )

    def _send_activity_task_started(
        self, context: RequestContext, task_token: TaskToken, worker_name: Optional[Name]
    ) -> None:
        executions: list[Execution] = self._get_executions(context)
        for execution in executions:
            callback_endpoint = execution.exec_worker.env.callback_pool_manager.get(
                callback_id=task_token
            )
            if isinstance(callback_endpoint, ActivityCallbackEndpoint):
                callback_endpoint.notify_activity_task_start(worker_name=worker_name)
                return
        raise InvalidToken()

    @staticmethod
    def _pull_activity_task(activity: Activity) -> Optional[ActivityTask]:
        seconds_left = 60
        while seconds_left > 0:
            try:
                return activity.get_task()
            except IndexError:
                time.sleep(1)
                seconds_left -= 1
        return None

    def get_activity_task(
        self, context: RequestContext, activity_arn: Arn, worker_name: Name = None, **kwargs
    ) -> GetActivityTaskOutput:
        self._validate_activity_arn(activity_arn)

        activity = self._get_activity(context=context, activity_arn=activity_arn)
        maybe_task: Optional[ActivityTask] = self._pull_activity_task(activity=activity)
        if maybe_task is not None:
            self._send_activity_task_started(
                context, maybe_task.task_token, worker_name=worker_name
            )
            return GetActivityTaskOutput(
                taskToken=maybe_task.task_token, input=maybe_task.task_input
            )

        return GetActivityTaskOutput(taskToken=None, input=None)
