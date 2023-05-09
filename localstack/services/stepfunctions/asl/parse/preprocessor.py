import json
from typing import Optional

from antlr4 import ParserRuleContext
from antlr4.tree.Tree import ParseTree, TerminalNodeImpl

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParserVisitor import ASLParserVisitor
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import Antlr4Utils
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catcher_decl import CatcherDecl
from localstack.services.stepfunctions.asl.component.common.catch.catcher_props import CatcherProps
from localstack.services.stepfunctions.asl.component.common.cause_decl import CauseDecl
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.error_decl import ErrorDecl
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_equals_decl import (
    ErrorEqualsDecl,
)
from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.output_path import OutputPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadarr.payload_arr import (
    PayloadArr,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding import (
    PayloadBinding,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding_intrinsic_func import (
    PayloadBindingIntrinsicFunc,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding_path import (
    PayloadBindingPath,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding_path_context_obj import (
    PayloadBindingPathContextObj,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadbinding.payload_binding_value import (
    PayloadBindingValue,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadtmpl.payload_tmpl import (
    PayloadTmpl,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_bool import (
    PayloadValueBool,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_float import (
    PayloadValueFloat,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_int import (
    PayloadValueInt,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_null import (
    PayloadValueNull,
)
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payloadvaluelit.payload_value_str import (
    PayloadValueStr,
)
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.backoff_rate_decl import (
    BackoffRateDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.interval_seconds_decl import (
    IntervalSecondsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_attempts_decl import (
    MaxAttemptsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.retrier_decl import RetrierDecl
from localstack.services.stepfunctions.asl.component.common.retry.retrier_props import RetrierProps
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule import (
    ChoiceRule,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule_stmt import (
    ChoiceRuleStmt,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.choices_decl import (
    ChoicesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison import (
    Comparison,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_composite import (
    ComparisonComposite,
    ComparisonCompositeAnd,
    ComparisonCompositeNot,
    ComparisonCompositeOr,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_func import (
    ComparisonFunc,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_props import (
    ComparisonProps,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.default_decl import (
    DefaultDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.state_choice import (
    StateChoice,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor import (
    ItemProcessor,
    ItemProcessorProps,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.state_map import (
    StateMap,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.branches_decl import (
    BranchesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.state_parallel import (
    StateParallel,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    LambdaResource,
    Resource,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_lambda import (
    StateTaskLambda,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.state_fail import StateFail
from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.component.state.state_pass.state_pass import StatePass
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.component.state.state_succeed.state_succeed import (
    StateSucceed,
)
from localstack.services.stepfunctions.asl.component.state.state_type import StateType
from localstack.services.stepfunctions.asl.component.state.state_wait.state_wait import StateWait
from localstack.services.stepfunctions.asl.component.state.state_wait.variable import Variable
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.seconds import (
    Seconds,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.seconds_path import (
    SecondsPath,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.timestamp import (
    Timestamp,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.timestamp_path import (
    TimestampPath,
)
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class Preprocessor(ASLParserVisitor):
    @staticmethod
    def _inner_string_of(parse_tree: ParseTree) -> Optional[str]:
        pt = Antlr4Utils.is_production(parse_tree) or Antlr4Utils.is_terminal(parse_tree)
        inner_str = pt.getText()
        if inner_str.startswith('"') and inner_str.endswith('"'):
            inner_str = inner_str[1:-1]
        return inner_str

    def visitComment_decl(self, ctx: ASLParser.Comment_declContext) -> Comment:
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return Comment(comment=inner_str)

    def visitStartat_decl(self, ctx: ASLParser.Startat_declContext) -> StartAt:
        inner_str = self._inner_string_of(
            parse_tree=ctx.keyword_or_string(),
        )
        return StartAt(start_at_name=inner_str)

    def visitStates_decl(self, ctx: ASLParser.States_declContext) -> States:
        states = States()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, CommonStateField):
                # TODO move check to setter or checker layer?
                if cmp.name in states.states:
                    raise ValueError(f"State redefinition {child.getText()}")
                states.states[cmp.name] = cmp
        return states

    def visitType_decl(self, ctx: ASLParser.Type_declContext) -> StateType:
        return self.visit(ctx.state_type())

    def visitState_type(self, ctx: ASLParser.State_typeContext) -> StateType:
        state_type: int = ctx.children[0].symbol.type
        return StateType(state_type)

    def visitResource_decl(self, ctx: ASLParser.Resource_declContext) -> Resource:
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return Resource.from_resource_arn(inner_str)

    def visitEnd_decl(self, ctx: ASLParser.End_declContext) -> End:
        bool_child: ParseTree = ctx.children[-1]
        bool_term: Optional[TerminalNodeImpl] = Antlr4Utils.is_terminal(bool_child)
        if bool_term is None:
            raise ValueError(f"Could not derive End from declaration context '{ctx.getText()}'")
        bool_term_rule: int = bool_term.getSymbol().type
        is_end = bool_term_rule == ASLLexer.TRUE
        return End(is_end=is_end)

    def visitNext_decl(self, ctx: ASLParser.Next_declContext) -> Next:
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return Next(name=inner_str)

    def visitResult_path_decl(self, ctx: ASLParser.Result_path_declContext) -> ResultPath:
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return ResultPath(result_path_src=inner_str)

    def visitInput_path_decl(self, ctx: ASLParser.Input_path_declContext) -> InputPath:
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return InputPath(input_path_src=inner_str)

    def visitOutput_path_decl(self, ctx: ASLParser.Output_path_declContext):
        inner_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return OutputPath(output_path=inner_str)

    def visitResult_decl(self, ctx: ASLParser.Result_declContext) -> Result:
        json_decl = ctx.json_value_decl()
        json_str: str = json_decl.getText()
        json_obj: json = json.loads(json_str)
        return Result(result_obj=json_obj)

    def visitParameters_decl(self, ctx: ASLParser.Parameters_declContext) -> Parameters:
        payload_tmpl: PayloadTmpl = self.visit(ctx.payload_tmpl_decl())
        return Parameters(payload_tmpl=payload_tmpl)

    def visitResult_selector_decl(
        self, ctx: ASLParser.Result_selector_declContext
    ) -> ResultSelector:
        payload_tmpl: PayloadTmpl = self.visit(ctx.payload_tmpl_decl())
        return ResultSelector(payload_tmpl=payload_tmpl)

    def visitBranches_decl(self, ctx: ASLParser.Branches_declContext) -> BranchesDecl:
        programs: list[Program] = []
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, Program):
                programs.append(cmp)
        return BranchesDecl(programs=programs)

    def visitState_decl_body(self, ctx: ASLParser.State_decl_bodyContext) -> StateProps:
        state_props = StateProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            state_props.add(cmp)
        return state_props

    def visitState_decl(self, ctx: ASLParser.State_declContext) -> CommonStateField:
        state_name = self._inner_string_of(parse_tree=ctx.state_name())
        state_props: StateProps = self.visit(ctx.state_decl_body())
        state_props.name = state_name
        return self._common_state_field_of(state_props=state_props)

    @staticmethod
    def _common_state_field_of(state_props: StateProps) -> CommonStateField:
        # TODO: use subtype loading strategy.
        match state_props.get(StateType):
            case StateType.Task:
                resource: Resource = state_props.get(Resource)
                if not resource:
                    raise ValueError("No Resource declaration in State Task.")
                if isinstance(resource, LambdaResource):
                    state = StateTaskLambda()
                elif isinstance(resource, ServiceResource):
                    state = StateTaskService.for_service(service_name=resource.service_name)
                else:
                    raise NotImplementedError(
                        f"Resource of type '{type(resource)}' are not supported: '{resource}'."
                    )
            case StateType.Pass:
                state = StatePass()
            case StateType.Choice:
                state = StateChoice()
            case StateType.Fail:
                state = StateFail()
            case StateType.Succeed:
                state = StateSucceed()
            case StateType.Wait:
                state = StateWait()
            case StateType.Map:
                state = StateMap()
            case StateType.Parallel:
                state = StateParallel()
            case None:
                raise TypeError("No Type declaration for State in context.")
            case unknown:
                raise TypeError(
                    f"Unknown StateType value '{unknown}' in StateProps object in context."  # noqa
                )
        state.from_state_props(state_props)
        return state

    def visitVariable_decl(self, ctx: ASLParser.Variable_declContext) -> Variable:
        value: str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return Variable(value=value)

    def visitComparison_op(self, ctx: ASLParser.Comparison_opContext) -> ComparisonOperatorType:
        try:
            operator_type: int = ctx.children[0].symbol.type
            return ComparisonOperatorType(operator_type)
        except Exception:
            raise ValueError(f"Could not derive ComparisonOperator from context '{ctx.getText()}'.")

    def visitComparison_func(self, ctx: ASLParser.Comparison_funcContext) -> ComparisonFunc:
        comparison_op: ComparisonOperatorType = self.visit(ctx.comparison_op())

        json_decl = ctx.json_value_decl()
        json_str: str = json_decl.getText()
        json_obj: json = json.loads(json_str)

        return ComparisonFunc(operator=comparison_op, value=json_obj)

    def visitDefault_decl(self, ctx: ASLParser.Default_declContext) -> DefaultDecl:
        state_name = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return DefaultDecl(state_name=state_name)

    def visitComparison(self, ctx: ASLParser.ComparisonContext) -> Comparison:
        props = ComparisonProps()
        for child in ctx.children:
            cmp: Component = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, ComparisonFunc):
                props.function = cmp
            elif isinstance(cmp, Variable):
                props.variable = cmp
        if not props.variable:
            raise ValueError(f"No Variable declaration for Comparison: '{ctx.getText()}'.")
        if not props.function:
            raise ValueError(f"No Function declaration for Comparison: '{ctx.getText()}'.")
        return Comparison(variable=props.variable, func=props.function)

    def visitChoice_operator(
        self, ctx: ASLParser.Choice_operatorContext
    ) -> ComparisonComposite.ChoiceOp:
        pt: Optional[TerminalNodeImpl] = Antlr4Utils.is_terminal(ctx.children[0])
        if not pt:
            raise ValueError(f"Could not derive ChoiceOperator in block '{ctx.getText()}'.")
        return ComparisonComposite.ChoiceOp(pt.symbol.type)

    def visitComparison_composite(
        self, ctx: ASLParser.Comparison_compositeContext
    ) -> ComparisonComposite:
        choice_op: ComparisonComposite.ChoiceOp = self.visit(ctx.choice_operator())
        rules: list[ChoiceRule] = list()
        for child in ctx.children[1:]:
            cmp: Optional[Component] = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, ChoiceRule):
                rules.append(cmp)

        match choice_op:
            case ComparisonComposite.ChoiceOp.Not:
                if len(rules) != 1:
                    raise ValueError(
                        f"ComparisonCompositeNot must carry only one ComparisonCompositeStmt in: '{ctx.getText()}'."
                    )
                return ComparisonCompositeNot(rule=rules[0])
            case ComparisonComposite.ChoiceOp.And:
                if len(rules) <= 1:
                    raise ValueError(
                        f"ComparisonCompositeAnd must carry two or more ComparisonCompositeStmt in: '{ctx.getText()}'."
                    )
                return ComparisonCompositeAnd(rules=rules)
            case ComparisonComposite.ChoiceOp.Or:
                if len(rules) <= 1:
                    raise ValueError(
                        f"ComparisonCompositeOr must carry two or more ComparisonCompositeStmt in: '{ctx.getText()}'."
                    )
                return ComparisonCompositeOr(rules=rules)

    def visitChoice_rule_stmt(self, ctx: ASLParser.Choice_rule_stmtContext) -> ChoiceRuleStmt:
        return self.visit(ctx.children[0])

    def visitChoice_rule(self, ctx: ASLParser.Choice_ruleContext) -> ChoiceRule:
        stmts: list[ChoiceRuleStmt] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, ChoiceRuleStmt):
                stmts.append(cmp)
        return ChoiceRule(stmts=stmts)

    def visitChoices_decl(self, ctx: ASLParser.Choices_declContext) -> ChoicesDecl:
        rules: list[ChoiceRule] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, ChoiceRule):
                rules.append(cmp)
        return ChoicesDecl(rules=rules)

    def visitError_decl(self, ctx: ASLParser.Error_declContext) -> ErrorDecl:
        error = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return ErrorDecl(error=error)

    def visitCause_decl(self, ctx: ASLParser.Cause_declContext) -> CauseDecl:
        cause = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return CauseDecl(cause=cause)

    def visitSeconds_decl(self, ctx: ASLParser.Seconds_declContext) -> Seconds:
        return Seconds(seconds=int(ctx.INT().getText()))

    def visitSeconds_path_decl(self, ctx: ASLParser.Seconds_path_declContext) -> SecondsPath:
        path = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return SecondsPath(path=path)

    def visitItems_path_decl(self, ctx: ASLParser.Items_path_declContext) -> ItemsPath:
        path = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return ItemsPath(items_path_src=path)

    def visitMax_concurrency_decl(
        self, ctx: ASLParser.Max_concurrency_declContext
    ) -> MaxConcurrency:
        return MaxConcurrency(num=int(ctx.INT().getText()))

    def visitMode_decl(self, ctx: ASLParser.Mode_declContext) -> Mode:
        mode_type: int = self.visit(ctx.mode_type())
        return Mode(mode_type)

    def visitMode_type(self, ctx: ASLParser.Mode_typeContext) -> int:
        return ctx.children[0].symbol.type

    def visitTimestamp_decl(self, ctx: ASLParser.Seconds_path_declContext) -> Timestamp:
        timestamp_str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        timestamp = Timestamp.parse_timestamp(timestamp_str)
        return Timestamp(timestamp=timestamp)

    def visitTimestamp_path_decl(self, ctx: ASLParser.Timestamp_path_declContext) -> TimestampPath:
        path = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return TimestampPath(path=path)

    def visitProcessor_config_decl(
        self, ctx: ASLParser.Processor_config_declContext
    ) -> ProcessorConfig:
        mode = ProcessorConfig.DEFAULT_MODE

        for child in ctx.children:
            cmp = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, Mode):
                mode = cmp

        return ProcessorConfig(mode=mode)

    def visitItem_processor_item(self, ctx: ASLParser.Item_processor_itemContext) -> Component:
        return self.visit(ctx.children[0])

    def visitItem_processor_decl(self, ctx: ASLParser.Item_processor_declContext) -> ItemProcessor:
        props = ItemProcessorProps()
        for child in ctx.children:
            cmp = self.visit(child)
            props.add(cmp)
        return ItemProcessor.from_props(props)

    def visitRetry_decl(self, ctx: ASLParser.Retry_declContext) -> RetryDecl:
        retriers: list[RetrierDecl] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, RetrierDecl):
                retriers.append(cmp)
        return RetryDecl(retriers=retriers)

    def visitRetrier_decl(self, ctx: ASLParser.Retrier_declContext) -> RetrierDecl:
        props = RetrierProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            props.add(cmp)
        return RetrierDecl.from_retrier_props(props=props)

    def visitRetrier_stmt(self, ctx: ASLParser.Retrier_stmtContext):
        return self.visit(ctx.children[0])

    def visitError_equals_decl(self, ctx: ASLParser.Error_equals_declContext) -> ErrorEqualsDecl:
        error_names: list[ErrorName] = list()
        for child in ctx.children:
            cmp = self.visit(child)
            if isinstance(cmp, ErrorName):
                error_names.append(cmp)
        return ErrorEqualsDecl(error_names=error_names)

    def visitError_name(self, ctx: ASLParser.Error_nameContext) -> ErrorName:
        pt = ctx.children[0]

        # Case: StatesErrorName.
        prc: Optional[ParserRuleContext] = Antlr4Utils.is_production(
            pt=pt, rule_index=ASLParser.RULE_states_error_name
        )
        if prc:
            return self.visit(prc)

        # Case CustomErrorName.
        error_name = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return CustomErrorName(error_name=error_name)

    def visitStates_error_name(self, ctx: ASLParser.States_error_nameContext) -> StatesErrorName:
        pt: Optional[TerminalNodeImpl] = Antlr4Utils.is_terminal(ctx.children[0])
        if not pt:
            raise ValueError(f"Could not derive ErrorName in block '{ctx.getText()}'.")
        states_error_name_type = StatesErrorNameType(pt.symbol.type)
        return StatesErrorName(states_error_name_type)

    def visitInterval_seconds_decl(
        self, ctx: ASLParser.Interval_seconds_declContext
    ) -> IntervalSecondsDecl:
        return IntervalSecondsDecl(seconds=int(ctx.INT().getText()))

    def visitMax_attempts_decl(self, ctx: ASLParser.Max_attempts_declContext) -> MaxAttemptsDecl:
        return MaxAttemptsDecl(attempts=int(ctx.INT().getText()))

    def visitBackoff_rate_decl(self, ctx: ASLParser.Backoff_rate_declContext) -> BackoffRateDecl:
        return BackoffRateDecl(rate=float(ctx.NUMBER().getText()))

    def visitCatch_decl(self, ctx: ASLParser.Catch_declContext) -> CatchDecl:
        catchers: list[CatcherDecl] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, CatcherDecl):
                catchers.append(cmp)
        return CatchDecl(catchers=catchers)

    def visitCatcher_decl(self, ctx: ASLParser.Catcher_declContext) -> CatcherDecl:
        props = CatcherProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            props.add(cmp)
        return CatcherDecl.from_catcher_props(props=props)

    def visitPayload_value_float(
        self, ctx: ASLParser.Payload_value_floatContext
    ) -> PayloadValueFloat:
        return PayloadValueFloat(val=float(ctx.NUMBER().getText()))

    def visitPayload_value_int(self, ctx: ASLParser.Payload_value_intContext) -> PayloadValueInt:
        return PayloadValueInt(val=int(ctx.INT().getText()))

    def visitPayload_value_bool(self, ctx: ASLParser.Payload_value_boolContext) -> PayloadValueBool:
        bool_child: ParseTree = ctx.children[0]
        bool_term: Optional[TerminalNodeImpl] = Antlr4Utils.is_terminal(bool_child)
        if bool_term is None:
            raise ValueError(
                f"Could not derive PayloadValueBool from declaration context '{ctx.getText()}'."
            )
        bool_term_rule: int = bool_term.getSymbol().type
        bool_val: bool = bool_term_rule == ASLLexer.TRUE
        return PayloadValueBool(val=bool_val)

    def visitPayload_value_null(self, ctx: ASLParser.Payload_value_nullContext) -> PayloadValueNull:
        return PayloadValueNull()

    def visitPayload_value_str(self, ctx: ASLParser.Payload_value_strContext) -> PayloadValueStr:
        str_val = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        return PayloadValueStr(val=str_val)

    def visitPayload_binding_path(
        self, ctx: ASLParser.Payload_binding_pathContext
    ) -> PayloadBindingPath:
        string_dollar: str = self._inner_string_of(parse_tree=ctx.STRINGDOLLAR())
        string_path: str = self._inner_string_of(parse_tree=ctx.STRINGPATH())
        return PayloadBindingPath.from_raw(string_dollar=string_dollar, string_path=string_path)

    def visitPayload_binding_path_context_obj(
        self, ctx: ASLParser.Payload_binding_path_context_objContext
    ) -> PayloadBindingPathContextObj:
        string_dollar: str = self._inner_string_of(parse_tree=ctx.STRINGDOLLAR())
        string_path_context_obj: str = self._inner_string_of(parse_tree=ctx.STRINGPATHCONTEXTOBJ())
        return PayloadBindingPathContextObj.from_raw(
            string_dollar=string_dollar, string_path_context_obj=string_path_context_obj
        )

    def visitPayload_binding_intrinsic_func(
        self, ctx: ASLParser.Payload_binding_intrinsic_funcContext
    ) -> PayloadBindingIntrinsicFunc:
        string_dollar: str = self._inner_string_of(parse_tree=ctx.STRINGDOLLAR())
        intrinsic_func: str = self._inner_string_of(parse_tree=ctx.intrinsic_func())
        return PayloadBindingIntrinsicFunc.from_raw(
            string_dollar=string_dollar, intrinsic_func=intrinsic_func
        )

    def visitPayload_binding_value(
        self, ctx: ASLParser.Payload_binding_valueContext
    ) -> PayloadBindingValue:
        field: str = self._inner_string_of(parse_tree=ctx.keyword_or_string())
        value: PayloadValue = self.visit(ctx.payload_value_decl())
        return PayloadBindingValue(field=field, value=value)

    def visitPayload_arr_decl(self, ctx: ASLParser.Payload_arr_declContext) -> PayloadArr:
        payload_values: list[PayloadValue] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, PayloadValue):
                payload_values.append(cmp)
        return PayloadArr(payload_values=payload_values)

    def visitPayload_tmpl_decl(self, ctx: ASLParser.Payload_tmpl_declContext) -> PayloadTmpl:
        payload_bindings: list[PayloadBinding] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, PayloadBinding):
                payload_bindings.append(cmp)
        return PayloadTmpl(payload_bindings=payload_bindings)

    def visitPayload_value_decl(self, ctx: ASLParser.Payload_value_declContext) -> PayloadValue:
        value = ctx.children[0]
        return self.visit(value)

    def visitProgram_decl(self, ctx: ASLParser.Program_declContext) -> Program:
        props = TypedProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            props.add(cmp)

        program = Program(
            start_at=props.get(
                typ=StartAt,
                raise_on_missing=ValueError(
                    f"No '{StartAt}' definition for Program in context: '{ctx.getText()}'."
                ),
            ),
            states=props.get(
                typ=States,
                raise_on_missing=ValueError(
                    f"No '{States}' definition for Program in context: '{ctx.getText()}'."
                ),
            ),
            comment=props.get(typ=Comment),
        )
        return program
