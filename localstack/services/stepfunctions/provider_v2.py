import datetime
import json
from typing import Optional

from localstack.aws.api import RequestContext
from localstack.aws.api.stepfunctions import (
    Arn,
    CreateStateMachineInput,
    CreateStateMachineOutput,
    DeleteStateMachineOutput,
    DescribeExecutionOutput,
    DescribeStateMachineOutput,
    ExecutionList,
    ExecutionStatus,
    GetExecutionHistoryOutput,
    IncludeExecutionDataGetExecutionHistory,
    InvalidExecutionInput,
    InvalidName,
    ListExecutionsOutput,
    ListExecutionsPageToken,
    ListStateMachinesOutput,
    LongArn,
    Name,
    PageSize,
    PageToken,
    ReverseOrder,
    SensitiveCause,
    SensitiveData,
    SensitiveError,
    StartExecutionOutput,
    StateMachineAlreadyExists,
    StateMachineDoesNotExist,
    StateMachineList,
    StateMachineStatus,
    StateMachineType,
    StepfunctionsApi,
    StopExecutionOutput,
    TraceHeader,
)
from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachine
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

    def _is_idempotent_create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> Optional[StateMachine]:
        # CreateStateMachine's idempotency check is based on the state machine name, definition, type,
        # LoggingConfiguration and TracingConfiguration.
        # If a following request has a different roleArn or tags, Step Functions will ignore these differences and
        # treat it as an idempotent request of the previous. In this case, roleArn and tags will not be updated, even
        # if they are different.
        state_machines: list[StateMachine] = list(self.get_store(context).state_machines.values())
        for state_machine in state_machines:
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

    def _state_machine_by_name(self, context: RequestContext, name: str) -> Optional[StateMachine]:
        state_machines: list[StateMachine] = list(self.get_store(context).state_machines.values())
        for state_machine in state_machines:
            if state_machine.name == name:
                return state_machine
        return None

    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> CreateStateMachineOutput:
        # CreateStateMachine is an idempotent API. Subsequent requests won’t create a duplicate resource if it was
        # already created.
        idem_state_machine: Optional[StateMachine] = self._is_idempotent_create_state_machine(
            context=context, request=request
        )
        if idem_state_machine is not None:
            return CreateStateMachineOutput(
                stateMachineArn=idem_state_machine.arn, creationDate=idem_state_machine.create_date
            )

        state_machine_with_name: Optional[StateMachine] = self._state_machine_by_name(
            context=context, name=request["name"]
        )
        if state_machine_with_name is not None:
            raise StateMachineAlreadyExists(
                f"State Machine Already Exists: '{state_machine_with_name.arn}'"
            )

        name: Optional[Name] = request["name"]
        arn = aws_stack_state_machine_arn(
            name=name, account_id=context.account_id, region_name=context.region
        )

        if not name and arn in self.get_store(context).state_machines:
            raise InvalidName()

        state_machine = StateMachine(
            name=name,
            arn=arn,
            role_arn=request["roleArn"],
            definition=request["definition"],
            sm_type=request.get("type"),
            logging_config=request.get("loggingConfiguration"),
            tags=request.get("tags"),
            tracing_config=request.get("tracingConfiguration"),
        )

        self.get_store(context).state_machines[arn] = state_machine

        return CreateStateMachineOutput(
            stateMachineArn=state_machine.arn, creationDate=datetime.datetime.now()
        )

    def describe_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DescribeStateMachineOutput:
        sm = self.get_store(context).state_machines.get(state_machine_arn)
        return DescribeStateMachineOutput(
            stateMachineArn=sm.arn,
            name=sm.name,
            status=StateMachineStatus.ACTIVE,
            definition=sm.definition,
            roleArn=sm.role_arn,
            type=sm.sm_type,
            creationDate=sm.create_date,
            loggingConfiguration=sm.logging_config,
        )

    def start_execution(
        self,
        context: RequestContext,
        state_machine_arn: Arn,
        name: Name = None,
        input: SensitiveData = None,
        trace_header: TraceHeader = None,
    ) -> StartExecutionOutput:
        state_machine: Optional[StateMachine] = self.get_store(context).state_machines.get(
            state_machine_arn
        )
        if not state_machine:
            raise StateMachineDoesNotExist(f"State Machine Does Not Exist: '{state_machine_arn}'")

        if input is None:
            input_data = None
        else:
            try:
                input_data = json.loads(input)
            except Exception as ex:
                raise InvalidExecutionInput(str(ex))  # TODO: report parsing error like AWS.

        exec_name = long_uid()
        arn_data: ArnData = parse_arn(state_machine_arn)
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
            role_arn=state_machine.role_arn,
            exec_arn=exec_arn,
            state_machine=state_machine,
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
        ]
        return ListExecutionsOutput(executions=executions)

    def list_state_machines(
        self, context: RequestContext, max_results: PageSize = None, next_token: PageToken = None
    ) -> ListStateMachinesOutput:
        # TODO: add paging support.
        state_machines: StateMachineList = [
            sm.to_state_machine_list_item()
            for sm in self.get_store(context).state_machines.values()
        ]
        state_machines.sort(key=lambda si: si["creationDate"])
        return ListStateMachinesOutput(stateMachines=state_machines)

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
        self.get_store(context).state_machines.pop(state_machine_arn, None)
        return DeleteStateMachineOutput()

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
