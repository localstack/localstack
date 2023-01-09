import datetime
from typing import Optional

from localstack.aws.accounts import get_aws_account_id
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
    StateMachineStatus,
    StepfunctionsApi,
    StopExecutionOutput,
    TraceHeader,
)
from localstack.services.stepfunctions.backend.execution import Execution
from localstack.services.stepfunctions.backend.state_machine import StateMachine
from localstack.services.stepfunctions.backend.store import SFNStore, sfn_stores
from localstack.utils.aws import aws_stack
from localstack.utils.aws.arns import state_machine_arn as aws_stack_state_machine_arn
from localstack.utils.aws.arns import state_machine_arn as aws_stack_stepfunctions_activity_arn


class StepfunctionsProvider(StepfunctionsApi):
    @staticmethod
    def get_store() -> SFNStore:
        return sfn_stores[get_aws_account_id()][aws_stack.get_region()]

    def _get_state_machine(self, state_machine_arn: Arn) -> StateMachine:
        state_machine: Optional[StateMachine] = self.get_store().sm_by_arn.get(state_machine_arn)
        if not state_machine:
            raise InvalidName()  # TODO
        return state_machine

    def _get_execution(self, execution_arn: Arn) -> Execution:
        execution: Optional[Execution] = self.get_store().execs_by_exec_arn.get(execution_arn)
        if not execution:
            raise InvalidName()  # TODO
        return execution

    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> CreateStateMachineOutput:
        # TODO.
        name: Optional[Name] = request["name"]
        arn = aws_stack_state_machine_arn(
            name=name, account_id=context.account_id, region_name=context.region
        )

        if not name and arn in self.get_store().sm_by_arn:
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

        self.get_store().sm_by_arn[arn] = state_machine

        return CreateStateMachineOutput(
            stateMachineArn=state_machine.arn, creationDate=datetime.datetime.now()
        )

    def describe_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DescribeStateMachineOutput:
        sm = self.get_store().sm_by_arn.get(state_machine_arn)
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
        state_machine: Optional[StateMachine] = self.get_store().sm_by_arn.get(state_machine_arn)
        if not state_machine:
            raise InvalidName()  # TODO

        # TODO: generate execution arn instead?.
        exec_arn = aws_stack_stepfunctions_activity_arn(
            name=state_machine.name, account_id=context.account_id, region_name=context.region
        )

        if exec_arn in self.get_store().execs_by_exec_arn:
            raise InvalidName()  # TODO

        execution = Execution(
            exec_arn=exec_arn,
            state_machine=state_machine,
            start_date=datetime.datetime.now(),
            input_data=input,
            trace_header=trace_header,
        )
        self.get_store().execs_by_exec_arn[exec_arn] = execution

        execution.start()
        return execution.to_start_output()

    def describe_execution(
        self, context: RequestContext, execution_arn: Arn
    ) -> DescribeExecutionOutput:
        execution: Execution = self._get_execution(execution_arn=execution_arn)
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
            for execution in self.get_store().execs_by_exec_arn.values()
        ]
        return ListExecutionsOutput(executions=executions)

    def list_state_machines(
        self, context: RequestContext, max_results: PageSize = None, next_token: PageToken = None
    ) -> ListStateMachinesOutput:
        # TODO: add paging support.
        return ListStateMachinesOutput(
            stateMachines=[
                sm.to_state_machine_list_item() for sm in self.get_store().sm_by_arn.values()
            ]
        )

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
        execution: Execution = self._get_execution(execution_arn=execution_arn)
        history: GetExecutionHistoryOutput = execution.to_history_output()
        return history

    def delete_state_machine(
        self, context: RequestContext, state_machine_arn: Arn
    ) -> DeleteStateMachineOutput:
        # TODO: halt executions?
        state_machine = self._get_state_machine(state_machine_arn=state_machine_arn)
        # Failure of getter is handled implicitly.
        del self.get_store().sm_by_arn[state_machine.arn]
        return DeleteStateMachineOutput()

    def stop_execution(
        self,
        context: RequestContext,
        execution_arn: Arn,
        error: SensitiveError = None,
        cause: SensitiveCause = None,
    ) -> StopExecutionOutput:
        execution: Execution = self._get_execution(execution_arn=execution_arn)
        stop_date = datetime.datetime.now()
        execution.stop(stop_date=stop_date, cause=cause, error=error)
        return StopExecutionOutput(stopDate=stop_date)
