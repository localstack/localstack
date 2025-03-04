import json
import logging
from typing import Any, Optional

from antlr4 import ParserRuleContext
from antlr4.tree.Tree import ParseTree, TerminalNodeImpl

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParserVisitor import ASLParserVisitor
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import (
    from_string_literal,
    is_production,
    is_terminal,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_decl import AssignDecl
from localstack.services.stepfunctions.asl.component.common.assign.assign_decl_binding import (
    AssignDeclBinding,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_binding import (
    AssignTemplateBinding,
    AssignTemplateBindingStringExpressionSimple,
    AssignTemplateBindingValue,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value import (
    AssignTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value_array import (
    AssignTemplateValueArray,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value_object import (
    AssignTemplateValueObject,
)
from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value_terminal import (
    AssignTemplateValueTerminal,
    AssignTemplateValueTerminalLit,
    AssignTemplateValueTerminalStringJSONata,
)
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catcher_decl import CatcherDecl
from localstack.services.stepfunctions.asl.component.common.catch.catcher_props import CatcherProps
from localstack.services.stepfunctions.asl.component.common.comment import Comment
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
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_binding import (
    JSONataTemplateBinding,
)
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value import (
    JSONataTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_array import (
    JSONataTemplateValueArray,
)
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_object import (
    JSONataTemplateValueObject,
)
from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_terminal import (
    JSONataTemplateValueTerminalLit,
    JSONataTemplateValueTerminalStringJSONata,
)
from localstack.services.stepfunctions.asl.component.common.outputdecl import Output
from localstack.services.stepfunctions.asl.component.common.parargs import (
    ArgumentsJSONataTemplateValueObject,
    ArgumentsStringJSONata,
    Parameters,
    Parargs,
)
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
    PayloadBindingStringExpressionSimple,
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
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguage,
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.backoff_rate_decl import (
    BackoffRateDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.interval_seconds_decl import (
    IntervalSecondsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.jitter_strategy_decl import (
    JitterStrategy,
    JitterStrategyDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_attempts_decl import (
    MaxAttemptsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.max_delay_seconds_decl import (
    MaxDelaySecondsDecl,
)
from localstack.services.stepfunctions.asl.component.common.retry.retrier_decl import RetrierDecl
from localstack.services.stepfunctions.asl.component.common.retry.retrier_props import RetrierProps
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringContextPath,
    StringExpression,
    StringExpressionSimple,
    StringIntrinsicFunction,
    StringJSONata,
    StringJsonPath,
    StringLiteral,
    StringSampler,
    StringVariableSample,
)
from localstack.services.stepfunctions.asl.component.common.timeouts.heartbeat import (
    HeartbeatSeconds,
    HeartbeatSecondsJSONata,
    HeartbeatSecondsPath,
)
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import (
    TimeoutSeconds,
    TimeoutSecondsJSONata,
    TimeoutSecondsPath,
)
from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.program.program import Program
from localstack.services.stepfunctions.asl.component.program.states import States
from localstack.services.stepfunctions.asl.component.program.version import Version
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.choice_rule import (
    ChoiceRule,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.choices_decl import (
    ChoicesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison import (
    ComparisonComposite,
    ComparisonCompositeAnd,
    ComparisonCompositeNot,
    ComparisonCompositeOr,
    ComparisonCompositeProps,
    ConditionJSONataLit,
    ConditionStringJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_func import (
    ComparisonFunc,
    ComparisonFuncStringVariableSample,
    ComparisonFuncValue,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_type import (
    Comparison,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_variable import (
    ComparisonVariable,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.variable import (
    Variable,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.default_decl import (
    DefaultDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.state_choice import (
    StateChoice,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.execution_type import (
    ExecutionType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.csv_header_location import (
    CSVHeaderLocation,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.csv_headers import (
    CSVHeaders,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.input_type import (
    InputType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.max_items_decl import (
    MaxItemsDecl,
    MaxItemsInt,
    MaxItemsPath,
    MaxItemsStringJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    ReaderConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_props import (
    ReaderConfigProps,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.items.items import (
    ItemsArray,
    ItemsJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.item_processor_decl import (
    ItemProcessorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_decl import (
    IteratorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.label import (
    Label,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
    MaxConcurrencyJSONata,
    MaxConcurrencyPath,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.result_writer.result_writer_decl import (
    ResultWriter,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.state_map import (
    StateMap,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.tolerated_failure import (
    ToleratedFailureCountInt,
    ToleratedFailureCountPath,
    ToleratedFailurePercentage,
    ToleratedFailurePercentagePath,
    ToleratedFailurePercentageStringJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.branches_decl import (
    BranchesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.state_parallel import (
    StateParallel,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    Credentials,
    RoleArn,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_factory import (
    state_task_for,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.cause_decl import (
    Cause,
    CausePath,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.error_decl import (
    Error,
    ErrorPath,
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
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.seconds import (
    Seconds,
    SecondsJSONata,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.seconds_path import (
    SecondsPath,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.timestamp import (
    Timestamp,
    TimestampPath,
)
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps

LOG = logging.getLogger(__name__)


class Preprocessor(ASLParserVisitor):
    _query_language_per_scope: list[QueryLanguage] = list()

    def _get_current_query_language(self) -> QueryLanguage:
        return self._query_language_per_scope[-1]

    def _open_query_language_scope(self, parse_tree: ParseTree) -> None:
        production = is_production(parse_tree)
        if production is None:
            raise RuntimeError(f"Cannot expect QueryLanguage definition at depth: {parse_tree}")

        # Extract the QueryLanguage declaration at this ParseTree level, if any.
        query_language = None
        for child in production.children:
            sub_production = is_production(child, ASLParser.RULE_top_layer_stmt) or is_production(
                child, ASLParser.RULE_state_stmt
            )
            if sub_production is not None:
                child = sub_production.children[0]
            sub_production = is_production(child, ASLParser.RULE_query_language_decl)
            if sub_production is not None:
                query_language = self.visit(sub_production)
                break

        # Check this is the initial scope, if so set the initial value to the declaration or the default.
        if not self._query_language_per_scope:
            if query_language is None:
                query_language = QueryLanguage()
        # Otherwise, check for logical conflicts and add the latest or inherited value to as the next scope.
        else:
            current_query_language = self._get_current_query_language()
            if query_language is None:
                query_language = current_query_language
            if (
                current_query_language.query_language_mode == QueryLanguageMode.JSONata
                and query_language.query_language_mode == QueryLanguageMode.JSONPath
            ):
                raise ValueError(
                    f"Cannot downgrade from JSONata context to a JSONPath context at: {parse_tree}"
                )

        self._query_language_per_scope.append(query_language)

    def _close_query_language_scope(self) -> None:
        self._query_language_per_scope.pop()

    def _is_query_language(self, query_language_mode: QueryLanguageMode) -> bool:
        current_query_language = self._get_current_query_language()
        return current_query_language.query_language_mode == query_language_mode

    def _raise_if_query_language_is_not(
        self, query_language_mode: QueryLanguageMode, ctx: ParserRuleContext
    ) -> None:
        if not self._is_query_language(query_language_mode=query_language_mode):
            raise ValueError(
                f"Unsupported declaration in QueryLanguage={query_language_mode} block: {ctx.getText()}"
            )

    @staticmethod
    def _inner_string_of(parser_rule_context: ParserRuleContext) -> Optional[str]:
        if is_terminal(parser_rule_context, ASLLexer.NULL):
            return None
        inner_str = parser_rule_context.getText()
        if inner_str.startswith('"') and inner_str.endswith('"'):
            inner_str = inner_str[1:-1]
        return inner_str

    def _inner_jsonata_expr(self, ctx: ParserRuleContext) -> str:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        inner_string_value = from_string_literal(parser_rule_context=ctx)
        # Strip the start and end jsonata symbols {%<body>%}
        expression_body = inner_string_value[2:-2]
        # Often leading and trailing spaces are used around the body: remove.
        expression = expression_body.strip()
        return expression

    def visitComment_decl(self, ctx: ASLParser.Comment_declContext) -> Comment:
        inner_str = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return Comment(comment=inner_str)

    def visitVersion_decl(self, ctx: ASLParser.Version_declContext) -> Version:
        version_str = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return Version(version=version_str)

    def visitStartat_decl(self, ctx: ASLParser.Startat_declContext) -> StartAt:
        inner_str = self._inner_string_of(parser_rule_context=ctx.string_literal())
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
        inner_str = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return Resource.from_resource_arn(inner_str)

    def visitEnd_decl(self, ctx: ASLParser.End_declContext) -> End:
        bool_child: ParseTree = ctx.children[-1]
        bool_term: Optional[TerminalNodeImpl] = is_terminal(bool_child)
        if bool_term is None:
            raise ValueError(f"Could not derive End from declaration context '{ctx.getText()}'")
        bool_term_rule: int = bool_term.getSymbol().type
        is_end = bool_term_rule == ASLLexer.TRUE
        return End(is_end=is_end)

    def visitNext_decl(self, ctx: ASLParser.Next_declContext) -> Next:
        inner_str = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return Next(name=inner_str)

    def visitResult_path_decl(self, ctx: ASLParser.Result_path_declContext) -> ResultPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        inner_str = self._inner_string_of(parser_rule_context=ctx.children[-1])
        return ResultPath(result_path_src=inner_str)

    def visitInput_path_decl(self, ctx: ASLParser.Input_path_declContext) -> InputPath:
        string_sampler: Optional[StringSampler] = None
        if not is_terminal(pt=ctx.children[-1], token_type=ASLLexer.NULL):
            string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return InputPath(string_sampler=string_sampler)

    def visitOutput_path_decl(self, ctx: ASLParser.Output_path_declContext) -> OutputPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: Optional[StringSampler] = None
        if is_production(ctx.children[-1], ASLParser.RULE_string_sampler):
            string_sampler: StringSampler = self.visitString_sampler(ctx.children[-1])
        return OutputPath(string_sampler=string_sampler)

    def visitResult_decl(self, ctx: ASLParser.Result_declContext) -> Result:
        json_decl = ctx.json_value_decl()
        json_str: str = json_decl.getText()
        json_obj: json = json.loads(json_str)
        return Result(result_obj=json_obj)

    def visitParameters_decl(self, ctx: ASLParser.Parameters_declContext) -> Parameters:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        payload_tmpl: PayloadTmpl = self.visit(ctx.payload_tmpl_decl())
        return Parameters(payload_tmpl=payload_tmpl)

    def visitTimeout_seconds_int(self, ctx: ASLParser.Timeout_seconds_intContext) -> TimeoutSeconds:
        seconds = int(ctx.INT().getText())
        return TimeoutSeconds(timeout_seconds=seconds)

    def visitTimeout_seconds_jsonata(
        self, ctx: ASLParser.Timeout_seconds_jsonataContext
    ) -> TimeoutSecondsJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return TimeoutSecondsJSONata(string_jsonata=string_jsonata)

    def visitTimeout_seconds_path(
        self, ctx: ASLParser.Timeout_seconds_pathContext
    ) -> TimeoutSecondsPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return TimeoutSecondsPath(string_sampler=string_sampler)

    def visitHeartbeat_seconds_int(
        self, ctx: ASLParser.Heartbeat_seconds_intContext
    ) -> HeartbeatSeconds:
        seconds = int(ctx.INT().getText())
        return HeartbeatSeconds(heartbeat_seconds=seconds)

    def visitHeartbeat_seconds_jsonata(
        self, ctx: ASLParser.Heartbeat_seconds_jsonataContext
    ) -> HeartbeatSecondsJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return HeartbeatSecondsJSONata(string_jsonata=string_jsonata)

    def visitHeartbeat_seconds_path(
        self, ctx: ASLParser.Heartbeat_seconds_pathContext
    ) -> HeartbeatSecondsPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return HeartbeatSecondsPath(string_sampler=string_sampler)

    def visitResult_selector_decl(
        self, ctx: ASLParser.Result_selector_declContext
    ) -> ResultSelector:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
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
        self._open_query_language_scope(ctx)
        state_props = StateProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            state_props.add(cmp)
        if state_props.get(QueryLanguage) is None:
            state_props.add(self._get_current_query_language())
        self._close_query_language_scope()
        return state_props

    def visitState_decl(self, ctx: ASLParser.State_declContext) -> CommonStateField:
        state_name = self._inner_string_of(parser_rule_context=ctx.string_literal())
        state_props: StateProps = self.visit(ctx.state_decl_body())
        state_props.name = state_name
        common_state_field = self._common_state_field_of(state_props=state_props)
        return common_state_field

    @staticmethod
    def _common_state_field_of(state_props: StateProps) -> CommonStateField:
        # TODO: use subtype loading strategy.
        match state_props.get(StateType):
            case StateType.Task:
                resource: Resource = state_props.get(Resource)
                state = state_task_for(resource)
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

    def visitCondition_lit(self, ctx: ASLParser.Condition_litContext) -> ConditionJSONataLit:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        bool_child: ParseTree = ctx.children[-1]
        bool_term: Optional[TerminalNodeImpl] = is_terminal(bool_child)
        if bool_term is None:
            raise ValueError(
                f"Could not derive boolean literal from declaration context '{ctx.getText()}'."
            )
        bool_term_rule: int = bool_term.getSymbol().type
        bool_val: bool = bool_term_rule == ASLLexer.TRUE
        return ConditionJSONataLit(literal=bool_val)

    def visitCondition_string_jsonata(
        self, ctx: ASLParser.Condition_string_jsonataContext
    ) -> ConditionStringJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx=ctx.string_jsonata())
        return ConditionStringJSONata(string_jsonata=string_jsonata)

    def visitVariable_decl(self, ctx: ASLParser.Variable_declContext) -> Variable:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx=ctx.string_sampler())
        return Variable(string_sampler=string_sampler)

    def visitComparison_op(self, ctx: ASLParser.Comparison_opContext) -> ComparisonOperatorType:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        try:
            operator_type: int = ctx.children[0].symbol.type
            return ComparisonOperatorType(operator_type)
        except Exception:
            raise ValueError(f"Could not derive ComparisonOperator from context '{ctx.getText()}'.")

    def visitComparison_func_value(
        self, ctx: ASLParser.Comparison_func_valueContext
    ) -> ComparisonFuncValue:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        comparison_op: ComparisonOperatorType = self.visit(ctx.comparison_op())
        json_decl = ctx.json_value_decl()
        json_str: str = json_decl.getText()
        json_obj: Any = json.loads(json_str)
        return ComparisonFuncValue(operator_type=comparison_op, value=json_obj)

    def visitComparison_func_string_variable_sample(
        self, ctx: ASLParser.Comparison_func_string_variable_sampleContext
    ) -> ComparisonFuncStringVariableSample:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        comparison_op: ComparisonOperatorType = self.visit(ctx.comparison_op())
        string_variable_sample: StringVariableSample = self.visitString_variable_sample(
            ctx.string_variable_sample()
        )
        return ComparisonFuncStringVariableSample(
            operator_type=comparison_op, string_variable_sample=string_variable_sample
        )

    def visitDefault_decl(self, ctx: ASLParser.Default_declContext) -> DefaultDecl:
        state_name = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return DefaultDecl(state_name=state_name)

    def visitChoice_operator(
        self, ctx: ASLParser.Choice_operatorContext
    ) -> ComparisonComposite.ChoiceOp:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        pt: Optional[TerminalNodeImpl] = is_terminal(ctx.children[0])
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
                return ComparisonCompositeAnd(rules=rules)
            case ComparisonComposite.ChoiceOp.Or:
                return ComparisonCompositeOr(rules=rules)

    def visitChoice_rule_comparison_composite(
        self, ctx: ASLParser.Choice_rule_comparison_compositeContext
    ) -> ChoiceRule:
        composite_stmts = ComparisonCompositeProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            composite_stmts.add(cmp)
        return ChoiceRule(
            comparison=composite_stmts.get(
                typ=ComparisonComposite,
                raise_on_missing=ValueError(
                    f"Expecting a 'ComparisonComposite' definition at '{ctx.getText()}'."
                ),
            ),
            next_stmt=composite_stmts.get(Next),
            comment=composite_stmts.get(Comment),
            assign=composite_stmts.get(AssignDecl),
            output=composite_stmts.get(Output),
        )

    def visitChoice_rule_comparison_variable(
        self, ctx: ASLParser.Choice_rule_comparison_variableContext
    ) -> ChoiceRule:
        comparison_stmts = StateProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            comparison_stmts.add(cmp)
        if self._is_query_language(query_language_mode=QueryLanguageMode.JSONPath):
            variable: Variable = comparison_stmts.get(
                typ=Variable,
                raise_on_missing=ValueError(
                    f"Expected a Variable declaration in '{ctx.getText()}'."
                ),
            )
            comparison_func: Comparison = comparison_stmts.get(
                typ=Comparison,
                raise_on_missing=ValueError(
                    f"Expected a ComparisonFunction declaration in '{ctx.getText()}'."
                ),
            )
            if not isinstance(comparison_func, ComparisonFunc):
                raise ValueError(f"Expected a ComparisonFunction declaration in '{ctx.getText()}'")
            comparison_variable = ComparisonVariable(variable=variable, func=comparison_func)
            return ChoiceRule(
                comparison=comparison_variable,
                next_stmt=comparison_stmts.get(Next),
                comment=comparison_stmts.get(Comment),
                assign=None,
                output=None,
            )
        else:
            condition: Comparison = comparison_stmts.get(
                typ=Comparison,
                raise_on_missing=ValueError(
                    f"Expected a Condition declaration in '{ctx.getText()}'"
                ),
            )
            return ChoiceRule(
                comparison=condition,
                next_stmt=comparison_stmts.get(Next),
                comment=comparison_stmts.get(Comment),
                assign=comparison_stmts.get(AssignDecl),
                output=comparison_stmts.get(Output),
            )

    def visitChoices_decl(self, ctx: ASLParser.Choices_declContext) -> ChoicesDecl:
        rules: list[ChoiceRule] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if not cmp:
                continue
            elif isinstance(cmp, ChoiceRule):
                rules.append(cmp)
        return ChoicesDecl(rules=rules)

    def visitError(self, ctx: ASLParser.ErrorContext) -> Error:
        string_expression: StringExpression = self.visit(ctx.children[-1])
        return Error(string_expression=string_expression)

    def visitError_path(self, ctx: ASLParser.Error_pathContext) -> ErrorPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_expression: StringExpression = self.visit(ctx.children[-1])
        return ErrorPath(string_expression=string_expression)

    def visitCause(self, ctx: ASLParser.CauseContext) -> Cause:
        string_expression: StringExpression = self.visit(ctx.children[-1])
        return Cause(string_expression=string_expression)

    def visitCause_path(self, ctx: ASLParser.Cause_pathContext) -> CausePath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_expression: StringExpression = self.visit(ctx.children[-1])
        return CausePath(string_expression=string_expression)

    def visitRole_arn(self, ctx: ASLParser.Role_arnContext) -> RoleArn:
        string_expression: StringExpression = self.visit(ctx.children[-1])
        return RoleArn(string_expression=string_expression)

    def visitRole_path(self, ctx: ASLParser.Role_pathContext) -> RoleArn:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_expression_simple: StringExpressionSimple = self.visitString_expression_simple(
            ctx=ctx.string_expression_simple()
        )
        return RoleArn(string_expression=string_expression_simple)

    def visitCredentials_decl(self, ctx: ASLParser.Credentials_declContext) -> Credentials:
        role_arn: RoleArn = self.visit(ctx.role_arn_decl())
        return Credentials(role_arn=role_arn)

    def visitSeconds_int(self, ctx: ASLParser.Seconds_intContext) -> Seconds:
        return Seconds(seconds=int(ctx.INT().getText()))

    def visitSeconds_jsonata(self, ctx: ASLParser.Seconds_jsonataContext) -> SecondsJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return SecondsJSONata(string_jsonata=string_jsonata)

    def visitSeconds_path(self, ctx: ASLParser.Seconds_pathContext) -> SecondsPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx=ctx.string_sampler())
        return SecondsPath(string_sampler=string_sampler)

    def visitItems_path_decl(self, ctx: ASLParser.Items_path_declContext) -> ItemsPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return ItemsPath(string_sampler=string_sampler)

    def visitMax_concurrency_int(self, ctx: ASLParser.Max_concurrency_intContext) -> MaxConcurrency:
        return MaxConcurrency(num=int(ctx.INT().getText()))

    def visitMax_concurrency_jsonata(
        self, ctx: ASLParser.Max_concurrency_jsonataContext
    ) -> MaxConcurrencyJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return MaxConcurrencyJSONata(string_jsonata=string_jsonata)

    def visitMax_concurrency_path(
        self, ctx: ASLParser.Max_concurrency_pathContext
    ) -> MaxConcurrencyPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return MaxConcurrencyPath(string_sampler=string_sampler)

    def visitMode_decl(self, ctx: ASLParser.Mode_declContext) -> Mode:
        mode_type: int = self.visit(ctx.mode_type())
        return Mode(mode_type)

    def visitMode_type(self, ctx: ASLParser.Mode_typeContext) -> int:
        return ctx.children[0].symbol.type

    def visitExecution_decl(self, ctx: ASLParser.Execution_declContext) -> ExecutionType:
        execution_type: int = self.visit(ctx.execution_type())
        return ExecutionType(execution_type)

    def visitExecution_type(self, ctx: ASLParser.Execution_typeContext) -> int:
        return ctx.children[0].symbol.type

    def visitTimestamp(self, ctx: ASLParser.TimestampContext) -> Timestamp:
        string: StringExpression = self.visit(ctx.children[-1])
        return Timestamp(string=string)

    def visitTimestamp_path(self, ctx: ASLParser.Timestamp_pathContext) -> TimestampPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return TimestampPath(string=string_sampler)

    def visitProcessor_config_decl(
        self, ctx: ASLParser.Processor_config_declContext
    ) -> ProcessorConfig:
        props = TypedProps()
        for child in ctx.children:
            cmp = self.visit(child)
            props.add(cmp)
        return ProcessorConfig(
            mode=props.get(typ=Mode) or ProcessorConfig.DEFAULT_MODE,
            execution_type=props.get(typ=ExecutionType) or ProcessorConfig.DEFAULT_EXECUTION_TYPE,
        )

    def visitItem_processor_item(self, ctx: ASLParser.Item_processor_itemContext) -> Component:
        return self.visit(ctx.children[0])

    def visitItem_processor_decl(
        self, ctx: ASLParser.Item_processor_declContext
    ) -> ItemProcessorDecl:
        props = TypedProps()
        for child in ctx.children:
            cmp = self.visit(child)
            props.add(cmp)
        return ItemProcessorDecl(
            query_language=props.get(QueryLanguage) or QueryLanguage(),
            start_at=props.get(
                typ=StartAt,
                raise_on_missing=ValueError(
                    f"Expected a StartAt declaration at '{ctx.getText()}'."
                ),
            ),
            states=props.get(
                typ=States,
                raise_on_missing=ValueError(f"Expected a States declaration at '{ctx.getText()}'."),
            ),
            comment=props.get(typ=Comment),
            processor_config=props.get(typ=ProcessorConfig) or ProcessorConfig(),
        )

    def visitIterator_decl(self, ctx: ASLParser.Iterator_declContext) -> IteratorDecl:
        props = TypedProps()
        for child in ctx.children:
            cmp = self.visit(child)
            props.add(cmp)
        return IteratorDecl(
            comment=props.get(typ=Comment),
            query_language=self._get_current_query_language(),
            start_at=props.get(
                typ=StartAt,
                raise_on_missing=ValueError(
                    f"Expected a StartAt declaration at '{ctx.getText()}'."
                ),
            ),
            states=props.get(
                typ=States,
                raise_on_missing=ValueError(f"Expected a States declaration at '{ctx.getText()}'."),
            ),
            processor_config=props.get(typ=ProcessorConfig) or ProcessorConfig(),
        )

    def visitItem_selector_decl(self, ctx: ASLParser.Item_selector_declContext) -> ItemSelector:
        template_value_object = self.visitAssign_template_value_object(
            ctx=ctx.assign_template_value_object()
        )
        return ItemSelector(template_value_object=template_value_object)

    def visitItem_reader_decl(self, ctx: ASLParser.Item_reader_declContext) -> ItemReader:
        props = StateProps()
        for child in ctx.children[3:-1]:
            cmp = self.visit(child)
            props.add(cmp)
        resource: Resource = props.get(
            typ=Resource,
            raise_on_missing=ValueError(f"Expected a Resource declaration at '{ctx.getText()}'."),
        )
        return ItemReader(
            resource=resource,
            parargs=props.get(Parargs),
            reader_config=props.get(ReaderConfig),
        )

    def visitReader_config_decl(self, ctx: ASLParser.Reader_config_declContext) -> ReaderConfig:
        props = ReaderConfigProps()
        for child in ctx.children:
            cmp = self.visit(child)
            props.add(cmp)
        return ReaderConfig(
            input_type=props.get(
                typ=InputType,
                raise_on_missing=ValueError(
                    f"Expected a InputType declaration at '{ctx.getText()}'."
                ),
            ),
            max_items_decl=props.get(typ=MaxItemsDecl),
            csv_header_location=props.get(CSVHeaderLocation),
            csv_headers=props.get(CSVHeaders),
        )

    def visitInput_type_decl(self, ctx: ASLParser.Input_type_declContext) -> InputType:
        input_type = self._inner_string_of(ctx.string_literal())
        return InputType(input_type=input_type)

    def visitCsv_header_location_decl(
        self, ctx: ASLParser.Csv_header_location_declContext
    ) -> CSVHeaderLocation:
        value = self._inner_string_of(ctx.string_literal())
        return CSVHeaderLocation(csv_header_location_value=value)

    def visitCsv_headers_decl(self, ctx: ASLParser.Csv_headers_declContext) -> CSVHeaders:
        csv_headers: list[str] = list()
        for child in ctx.children[3:-1]:
            maybe_str = is_production(pt=child, rule_index=ASLParser.RULE_string_literal)
            if maybe_str is not None:
                csv_headers.append(self._inner_string_of(maybe_str))
        # TODO: check for empty headers behaviour.
        return CSVHeaders(header_names=csv_headers)

    def visitMax_items_path(self, ctx: ASLParser.Max_items_pathContext) -> MaxItemsPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx=ctx.string_sampler())
        return MaxItemsPath(string_sampler=string_sampler)

    def visitMax_items_int(self, ctx: ASLParser.Max_items_intContext) -> MaxItemsInt:
        return MaxItemsInt(max_items=int(ctx.INT().getText()))

    def visitMax_items_string_jsonata(
        self, ctx: ASLParser.Max_items_string_jsonataContext
    ) -> MaxItemsStringJSONata:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return MaxItemsStringJSONata(string_jsonata=string_jsonata)

    def visitTolerated_failure_count_int(
        self, ctx: ASLParser.Tolerated_failure_count_intContext
    ) -> ToleratedFailureCountInt:
        LOG.warning(
            "ToleratedFailureCount declarations currently have no effect on the program evaluation."
        )
        count = int(ctx.INT().getText())
        return ToleratedFailureCountInt(tolerated_failure_count=count)

    def visitTolerated_failure_count_string_jsonata(
        self, ctx: ASLParser.Tolerated_failure_count_string_jsonataContext
    ) -> ToleratedFailurePercentageStringJSONata:
        LOG.warning(
            "ToleratedFailureCount declarations currently have no effect on the program evaluation."
        )
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx=ctx.string_jsonata())
        return ToleratedFailurePercentageStringJSONata(string_jsonata=string_jsonata)

    def visitTolerated_failure_count_path(
        self, ctx: ASLParser.Tolerated_failure_count_pathContext
    ) -> ToleratedFailureCountPath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        LOG.warning(
            "ToleratedFailureCountPath declarations currently have no effect on the program evaluation."
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return ToleratedFailureCountPath(string_sampler=string_sampler)

    def visitTolerated_failure_percentage_number(
        self, ctx: ASLParser.Tolerated_failure_percentage_numberContext
    ) -> ToleratedFailurePercentage:
        LOG.warning(
            "ToleratedFailurePercentage declarations currently have no effect on the program evaluation."
        )
        percentage = float(ctx.NUMBER().getText())
        return ToleratedFailurePercentage(tolerated_failure_percentage=percentage)

    def visitTolerated_failure_percentage_string_jsonata(
        self, ctx: ASLParser.Tolerated_failure_percentage_string_jsonataContext
    ) -> ToleratedFailurePercentageStringJSONata:
        LOG.warning(
            "ToleratedFailurePercentage declarations currently have no effect on the program evaluation."
        )
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx=ctx.string_jsonata())
        return ToleratedFailurePercentageStringJSONata(string_jsonata=string_jsonata)

    def visitTolerated_failure_percentage_path(
        self, ctx: ASLParser.Tolerated_failure_percentage_pathContext
    ) -> ToleratedFailurePercentagePath:
        self._raise_if_query_language_is_not(
            query_language_mode=QueryLanguageMode.JSONPath, ctx=ctx
        )
        LOG.warning(
            "ToleratedFailurePercentagePath declarations currently have no effect on the program evaluation."
        )
        string_sampler: StringSampler = self.visitString_sampler(ctx.string_sampler())
        return ToleratedFailurePercentagePath(string_sampler=string_sampler)

    def visitLabel_decl(self, ctx: ASLParser.Label_declContext) -> Label:
        label = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return Label(label=label)

    def visitResult_writer_decl(self, ctx: ASLParser.Result_writer_declContext) -> ResultWriter:
        props = StateProps()
        for child in ctx.children[3:-1]:
            cmp = self.visit(child)
            props.add(cmp)
        resource: Resource = props.get(
            typ=Resource,
            raise_on_missing=ValueError(f"Expected a Resource declaration at '{ctx.getText()}'."),
        )
        # TODO: add tests for arguments in jsonata blocks using result writer
        parargs: Parargs = props.get(
            typ=Parargs,
            raise_on_missing=ValueError(
                f"Expected a Parameters/Arguments declaration at '{ctx.getText()}'."
            ),
        )
        return ResultWriter(resource=resource, parargs=parargs)

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
        prc: Optional[ParserRuleContext] = is_production(
            pt=pt, rule_index=ASLParser.RULE_states_error_name
        )
        if prc:
            return self.visit(prc)

        # Case CustomErrorName.
        error_name = self._inner_string_of(parser_rule_context=ctx.string_literal())
        return CustomErrorName(error_name=error_name)

    def visitStates_error_name(self, ctx: ASLParser.States_error_nameContext) -> StatesErrorName:
        pt: Optional[TerminalNodeImpl] = is_terminal(ctx.children[0])
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
        return BackoffRateDecl(rate=float(ctx.children[-1].getText()))

    def visitMax_delay_seconds_decl(
        self, ctx: ASLParser.Max_delay_seconds_declContext
    ) -> MaxDelaySecondsDecl:
        return MaxDelaySecondsDecl(max_delays_seconds=int(ctx.INT().getText()))

    def visitJitter_strategy_decl(
        self, ctx: ASLParser.Jitter_strategy_declContext
    ) -> JitterStrategyDecl:
        last_child: ParseTree = ctx.children[-1]
        strategy_child: Optional[TerminalNodeImpl] = is_terminal(last_child)
        strategy_value = strategy_child.getSymbol().type
        jitter_strategy = JitterStrategy(strategy_value)
        return JitterStrategyDecl(jitter_strategy=jitter_strategy)

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
        if self._is_query_language(QueryLanguageMode.JSONPath) and not props.get(ResultPath):
            props.add(CatcherDecl.DEFAULT_RESULT_PATH)
        return CatcherDecl.from_catcher_props(props=props)

    def visitPayload_value_float(
        self, ctx: ASLParser.Payload_value_floatContext
    ) -> PayloadValueFloat:
        return PayloadValueFloat(val=float(ctx.NUMBER().getText()))

    def visitPayload_value_int(self, ctx: ASLParser.Payload_value_intContext) -> PayloadValueInt:
        return PayloadValueInt(val=int(ctx.INT().getText()))

    def visitPayload_value_bool(self, ctx: ASLParser.Payload_value_boolContext) -> PayloadValueBool:
        bool_child: ParseTree = ctx.children[0]
        bool_term: Optional[TerminalNodeImpl] = is_terminal(bool_child)
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
        string_literal: StringLiteral = self.visitString_literal(ctx=ctx.string_literal())
        return PayloadValueStr(val=string_literal.literal_value)

    def visitPayload_binding_sample(
        self, ctx: ASLParser.Payload_binding_sampleContext
    ) -> PayloadBindingStringExpressionSimple:
        string_dollar: str = self._inner_string_of(parser_rule_context=ctx.STRINGDOLLAR())
        field = string_dollar[:-2]
        string_expression_simple: StringExpressionSimple = self.visitString_expression_simple(
            ctx.string_expression_simple()
        )
        return PayloadBindingStringExpressionSimple(
            field=field, string_expression_simple=string_expression_simple
        )

    def visitPayload_binding_value(
        self, ctx: ASLParser.Payload_binding_valueContext
    ) -> PayloadBindingValue:
        string_literal: StringLiteral = self.visitString_literal(ctx=ctx.string_literal())
        payload_value: PayloadValue = self.visit(ctx.payload_value_decl())
        return PayloadBindingValue(field=string_literal.literal_value, payload_value=payload_value)

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
        self._open_query_language_scope(ctx)
        props = TypedProps()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            props.add(cmp)
        if props.get(QueryLanguage) is None:
            props.add(self._get_current_query_language())
        program = Program(
            query_language=props.get(typ=QueryLanguage) or QueryLanguage(),
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
            timeout_seconds=props.get(TimeoutSeconds),
            comment=props.get(typ=Comment),
            version=props.get(typ=Version),
        )
        self._close_query_language_scope()
        return program

    def visitState_machine(self, ctx: ASLParser.State_machineContext) -> Program:
        return self.visit(ctx.program_decl())

    def visitQuery_language_decl(self, ctx: ASLParser.Query_language_declContext) -> QueryLanguage:
        query_language_mode_int = ctx.children[-1].getSymbol().type
        query_language_mode = QueryLanguageMode(value=query_language_mode_int)
        return QueryLanguage(query_language_mode=query_language_mode)

    def visitAssign_template_value_terminal_float(
        self, ctx: ASLParser.Assign_template_value_terminal_floatContext
    ) -> AssignTemplateValueTerminalLit:
        float_value = float(ctx.NUMBER().getText())
        return AssignTemplateValueTerminalLit(value=float_value)

    def visitAssign_template_value_terminal_int(
        self, ctx: ASLParser.Assign_template_value_terminal_intContext
    ) -> AssignTemplateValueTerminalLit:
        int_value = int(ctx.INT().getText())
        return AssignTemplateValueTerminalLit(value=int_value)

    def visitAssign_template_value_terminal_bool(
        self, ctx: ASLParser.Assign_template_value_terminal_boolContext
    ) -> AssignTemplateValueTerminalLit:
        bool_term_rule: int = ctx.children[0].getSymbol().type
        bool_value: bool = bool_term_rule == ASLLexer.TRUE
        return AssignTemplateValueTerminalLit(value=bool_value)

    def visitAssign_template_value_terminal_null(
        self, ctx: ASLParser.Assign_template_value_terminal_nullContext
    ) -> AssignTemplateValueTerminalLit:
        return AssignTemplateValueTerminalLit(value=None)

    def visitAssign_template_value_terminal_string_jsonata(
        self, ctx: ASLParser.Assign_template_value_terminal_string_jsonataContext
    ) -> AssignTemplateValueTerminal:
        # Return a JSONata expression resolver or a suppressed depending on the current language mode.
        current_query_language = self._get_current_query_language()
        if current_query_language.query_language_mode == QueryLanguageMode.JSONata:
            string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
            return AssignTemplateValueTerminalStringJSONata(string_jsonata=string_jsonata)
        else:
            inner_string_value = self._inner_string_of(parser_rule_context=ctx.string_jsonata())
            return AssignTemplateValueTerminalLit(value=inner_string_value)

    def visitAssign_template_value_terminal_string_literal(
        self, ctx: ASLParser.Assign_template_value_terminal_string_literalContext
    ) -> AssignTemplateValueTerminal:
        string_literal = self._inner_string_of(ctx.string_literal())
        return AssignTemplateValueTerminalLit(value=string_literal)

    def visitAssign_template_value(self, ctx: ASLParser.Assign_template_valueContext):
        return self.visit(ctx.children[0])

    def visitAssign_template_value_array(
        self, ctx: ASLParser.Assign_template_value_arrayContext
    ) -> AssignTemplateValueArray:
        values: list[AssignTemplateValue] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, AssignTemplateValue):
                values.append(cmp)
        return AssignTemplateValueArray(values=values)

    def visitAssign_template_value_object(
        self, ctx: ASLParser.Assign_template_value_objectContext
    ) -> AssignTemplateValueObject:
        bindings: list[AssignTemplateBinding] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, AssignTemplateBinding):
                bindings.append(cmp)
        return AssignTemplateValueObject(bindings=bindings)

    def visitAssign_template_binding_value(
        self, ctx: ASLParser.Assign_template_binding_valueContext
    ) -> AssignTemplateBindingValue:
        string_literal: StringLiteral = self.visitString_literal(ctx=ctx.string_literal())
        assign_value: AssignTemplateValue = self.visit(ctx.assign_template_value())
        return AssignTemplateBindingValue(
            identifier=string_literal.literal_value, assign_value=assign_value
        )

    def visitAssign_template_binding_string_expression_simple(
        self, ctx: ASLParser.Assign_template_binding_string_expression_simpleContext
    ) -> AssignTemplateBindingStringExpressionSimple:
        identifier: str = self._inner_string_of(ctx.STRINGDOLLAR())
        identifier = identifier[:-2]
        string_expression_simple: StringExpressionSimple = self.visitString_expression_simple(
            ctx.string_expression_simple()
        )
        return AssignTemplateBindingStringExpressionSimple(
            identifier=identifier, string_expression_simple=string_expression_simple
        )

    def visitAssign_decl_binding(
        self, ctx: ASLParser.Assign_decl_bindingContext
    ) -> AssignDeclBinding:
        binding: AssignTemplateBinding = self.visit(ctx.assign_template_binding())
        return AssignDeclBinding(binding=binding)

    def visitAssign_decl_body(
        self, ctx: ASLParser.Assign_decl_bodyContext
    ) -> list[AssignDeclBinding]:
        bindings: list[AssignDeclBinding] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, AssignDeclBinding):
                bindings.append(cmp)
        return bindings

    def visitAssign_decl(self, ctx: ASLParser.Assign_declContext) -> AssignDecl:
        declaration_bindings: list[AssignDeclBinding] = self.visit(ctx.assign_decl_body())
        return AssignDecl(declaration_bindings=declaration_bindings)

    def visitJsonata_template_value_terminal_float(
        self, ctx: ASLParser.Jsonata_template_value_terminal_floatContext
    ) -> JSONataTemplateValueTerminalLit:
        float_value = float(ctx.NUMBER().getText())
        return JSONataTemplateValueTerminalLit(value=float_value)

    def visitJsonata_template_value_terminal_int(
        self, ctx: ASLParser.Jsonata_template_value_terminal_intContext
    ) -> JSONataTemplateValueTerminalLit:
        int_value = int(ctx.INT().getText())
        return JSONataTemplateValueTerminalLit(value=int_value)

    def visitJsonata_template_value_terminal_bool(
        self, ctx: ASLParser.Jsonata_template_value_terminal_boolContext
    ) -> JSONataTemplateValueTerminalLit:
        bool_term_rule: int = ctx.children[0].getSymbol().type
        bool_value: bool = bool_term_rule == ASLLexer.TRUE
        return JSONataTemplateValueTerminalLit(value=bool_value)

    def visitJsonata_template_value_terminal_null(
        self, ctx: ASLParser.Jsonata_template_value_terminal_nullContext
    ) -> JSONataTemplateValueTerminalLit:
        return JSONataTemplateValueTerminalLit(value=None)

    def visitJsonata_template_value_terminal_string_jsonata(
        self, ctx: ASLParser.Jsonata_template_value_terminal_string_jsonataContext
    ) -> JSONataTemplateValueTerminalStringJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return JSONataTemplateValueTerminalStringJSONata(string_jsonata=string_jsonata)

    def visitJsonata_template_value_terminal_string_literal(
        self, ctx: ASLParser.Jsonata_template_value_terminal_string_literalContext
    ) -> JSONataTemplateValueTerminalLit:
        string = from_string_literal(ctx.string_literal())
        return JSONataTemplateValueTerminalLit(value=string)

    def visitJsonata_template_value(
        self, ctx: ASLParser.Jsonata_template_valueContext
    ) -> JSONataTemplateValue:
        return self.visit(ctx.children[0])

    def visitJsonata_template_value_array(
        self, ctx: ASLParser.Jsonata_template_value_arrayContext
    ) -> JSONataTemplateValueArray:
        values: list[JSONataTemplateValue] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, JSONataTemplateValue):
                values.append(cmp)
        return JSONataTemplateValueArray(values=values)

    def visitJsonata_template_value_object(
        self, ctx: ASLParser.Jsonata_template_value_objectContext
    ) -> JSONataTemplateValueObject:
        bindings: list[JSONataTemplateBinding] = list()
        for child in ctx.children:
            cmp: Optional[Component] = self.visit(child)
            if isinstance(cmp, JSONataTemplateBinding):
                bindings.append(cmp)
        return JSONataTemplateValueObject(bindings=bindings)

    def visitJsonata_template_binding(
        self, ctx: ASLParser.Jsonata_template_bindingContext
    ) -> JSONataTemplateBinding:
        identifier: str = self._inner_string_of(ctx.string_literal())
        value: JSONataTemplateValue = self.visit(ctx.jsonata_template_value())
        return JSONataTemplateBinding(identifier=identifier, value=value)

    def visitArguments_string_jsonata(
        self, ctx: ASLParser.Arguments_string_jsonataContext
    ) -> ArgumentsStringJSONata:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return ArgumentsStringJSONata(string_jsonata=string_jsonata)

    def visitArguments_jsonata_template_value_object(
        self, ctx: ASLParser.Arguments_jsonata_template_value_objectContext
    ) -> ArgumentsJSONataTemplateValueObject:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        jsonata_template_value_object: JSONataTemplateValueObject = self.visit(
            ctx.jsonata_template_value_object()
        )
        return ArgumentsJSONataTemplateValueObject(
            jsonata_template_value_object=jsonata_template_value_object
        )

    def visitOutput_decl(self, ctx: ASLParser.Output_declContext) -> Output:
        jsonata_template_value: JSONataTemplateValue = self.visit(ctx.jsonata_template_value())
        return Output(jsonata_template_value=jsonata_template_value)

    def visitItems_array(self, ctx: ASLParser.Items_arrayContext) -> ItemsArray:
        jsonata_template_value_array: JSONataTemplateValueArray = self.visit(
            ctx.jsonata_template_value_array()
        )
        return ItemsArray(jsonata_template_value_array=jsonata_template_value_array)

    def visitItems_jsonata(self, ctx: ASLParser.Items_jsonataContext) -> ItemsJSONata:
        string_jsonata: StringJSONata = self.visitString_jsonata(ctx.string_jsonata())
        return ItemsJSONata(string_jsonata=string_jsonata)

    def visitString_sampler(self, ctx: ASLParser.String_samplerContext) -> StringSampler:
        return self.visit(ctx.children[0])

    def visitString_literal(self, ctx: ASLParser.String_literalContext) -> StringLiteral:
        string_literal = from_string_literal(parser_rule_context=ctx)
        return StringLiteral(literal_value=string_literal)

    def visitString_jsonpath(self, ctx: ASLParser.String_jsonpathContext) -> StringJsonPath:
        json_path: str = self._inner_string_of(parser_rule_context=ctx)
        return StringJsonPath(json_path=json_path)

    def visitString_context_path(
        self, ctx: ASLParser.String_context_pathContext
    ) -> StringContextPath:
        context_object_path: str = self._inner_string_of(parser_rule_context=ctx)
        return StringContextPath(context_object_path=context_object_path)

    def visitString_variable_sample(
        self, ctx: ASLParser.String_variable_sampleContext
    ) -> StringVariableSample:
        query_language_mode: QueryLanguageMode = (
            self._get_current_query_language().query_language_mode
        )
        expression: str = self._inner_string_of(parser_rule_context=ctx)
        return StringVariableSample(query_language_mode=query_language_mode, expression=expression)

    def visitString_jsonata(self, ctx: ASLParser.String_jsonataContext) -> StringJSONata:
        self._raise_if_query_language_is_not(query_language_mode=QueryLanguageMode.JSONata, ctx=ctx)
        expression = self._inner_jsonata_expr(ctx=ctx)
        return StringJSONata(expression=expression)

    def visitString_intrinsic_function(
        self, ctx: ASLParser.String_intrinsic_functionContext
    ) -> StringIntrinsicFunction:
        intrinsic_function_derivation = ctx.STRINGINTRINSICFUNC().getText()[1:-1]
        function, _ = IntrinsicParser.parse(intrinsic_function_derivation)
        return StringIntrinsicFunction(
            intrinsic_function_derivation=intrinsic_function_derivation, function=function
        )
