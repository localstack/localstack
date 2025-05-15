from __future__ import annotations

import copy
from typing import Optional, OrderedDict

from antlr4 import CommonTokenStream, InputStream
from antlr4.ParserRuleContext import ParserRuleContext
from antlr4.tree.Tree import TerminalNodeImpl

from localstack.services.stepfunctions.asl.antlr.runtime.LSLLexer import LSLLexer
from localstack.services.stepfunctions.asl.antlr.runtime.LSLParser import LSLParser
from localstack.services.stepfunctions.asl.antlr.runtime.LSLParserVisitor import LSLParserVisitor
from localstack.services.stepfunctions.asl.antlt4utils.antlr4utils import from_string_literal


def transpile(lsl_derivation: str) -> dict:
    input_stream = InputStream(lsl_derivation)
    lexer = LSLLexer(input_stream)
    stream = CommonTokenStream(lexer)
    parser = LSLParser(stream)
    tree = parser.state_machine()
    transpiler = _Transpiler()
    transpiler.visit(tree)
    workflow = transpiler.get_workflow()
    return workflow


class _Scope:
    _last_called: Optional[str]
    _state_templates: dict[str, dict]
    _start_at: Optional[str]
    _states: OrderedDict[str, dict]

    def __init__(self, upper_scope: Optional[_Scope] = None):
        self._last_called = None
        self._start_at = None
        if upper_scope is not None:
            self._state_templates = copy.deepcopy(upper_scope._state_templates)
        else:
            self._state_templates = dict()
        self._states = OrderedDict()

    def new_template(self, state_name: str, state: dict):
        self._state_templates[state_name] = state

    def get_template(self, state_name):
        template = self._state_templates[state_name]
        return copy.deepcopy(template)

    def set_next(self, state_name: str, state: dict):
        if self._start_at is None:
            self._start_at = state_name
        else:
            last_state = self._states[self._last_called]
            last_state.pop("End", None)
            last_state["Next"] = state_name
        self._last_called = state_name
        self._states[state_name] = state

    def to_scope_workflow(self) -> dict:
        return {"StartAt": self._start_at, "States": {**self._states}}


class _Transpiler(LSLParserVisitor):
    _scopes: list[_Scope]

    def __init__(self):
        self._scopes = list()
        self._scopes.append(_Scope())

    def get_workflow(self) -> dict:
        scope = self._this_scope()
        scope_workflow = scope.to_scope_workflow()
        workflow = {"Comment": "Auto-generated", "QueryLanguage": "JSONata", **scope_workflow}
        return workflow

    def _this_scope(self) -> _Scope:
        return self._scopes[-1]

    def visitState_declaration(self, ctx: LSLParser.State_declarationContext):
        state_name = from_string_literal(ctx.IDEN())
        state = self.visit(ctx.state_())
        state_type = state["Type"]
        if state_type not in {"Fail", "Pass"}:
            parameters = self.visitParameter_list(ctx.parameter_list())
            cleanup_assign = dict.fromkeys(parameters)
            state["Assign"] = cleanup_assign
            state["Output"] = "{% $states.result %}"

        scope = self._this_scope()
        scope.new_template(state_name=state_name, state=state)

        return state_name, state

    def transpile_inner_state_call(self, state_name: str, state: dict):
        scope = self._this_scope()
        scope.set_next(state_name=state_name, state=state)

    def visitState_call_named(self, ctx: LSLParser.State_call_namedContext):
        inner_name = from_string_literal(ctx.IDEN())
        state = self.visit(ctx.state_())
        self.transpile_inner_state_call(state_name=inner_name, state=state)

    def visitState_call_anonymous(self, ctx: LSLParser.State_call_anonymousContext):
        anonymous_inner_name = f"call:{ctx.start.line}:{ctx.start.column}"
        state = self.visit(ctx.state_())
        self.transpile_inner_state_call(state_name=anonymous_inner_name, state=state)

    def visitState_call_template(self, ctx: LSLParser.State_call_templateContext):
        scope = self._this_scope()
        call_marker = f"call:{ctx.start.line}:{ctx.start.column}"

        template_state_name = from_string_literal(ctx.IDEN())
        target_state_name = f"{call_marker}:{template_state_name}"
        target_state = scope.get_template(state_name=template_state_name)

        input_state_name = f"{target_state_name}:input"
        input_state = self.create_state_for_arg_assign_list(
            target_state_name=target_state_name, ctx=ctx.args_assign_list()
        )

        scope.set_next(state_name=input_state_name, state=input_state)
        scope.set_next(state_name=target_state_name, state=target_state)

        return target_state_name, input_state

    def create_state_for_arg_assign_list(
        self, target_state_name: str, ctx: LSLParser.Args_assign_listContext
    ):
        assign_body = self.visitArgs_assign_list(ctx=ctx)
        state = {"Type": "Pass", "Assign": assign_body, "Next": target_state_name}
        return state

    def visitArgs_assign_list(self, ctx: LSLParser.Args_assign_listContext):
        assign_body = dict()
        for child in ctx.children:
            if (
                isinstance(child, ParserRuleContext)
                and child.getRuleIndex() == LSLParser.RULE_args_assign
            ):
                variable_name, value = self.visitArgs_assign(child)  # noqa
                assign_body[variable_name] = value
        return assign_body

    def visitArgs_assign(self, ctx: LSLParser.Args_assignContext):
        variable_name = from_string_literal(ctx.IDEN())
        value = self.visit(ctx.json_value())
        return variable_name, value

    def visitParameter_list(self, ctx: LSLParser.Parameter_listContext):
        parameters = list()
        for child in ctx.children:
            if isinstance(child, TerminalNodeImpl) and child.symbol.type == LSLLexer.IDEN:
                parameter_identifier = from_string_literal(child)  # noqa
                parameters.append(parameter_identifier)
        return parameters

    def visitState_return(self, ctx: LSLParser.State_returnContext):
        output_expression = self.visit(ctx.json_value())
        output_prepare_state = {"Type": "Pass", "End": True, "Output": output_expression}
        return output_prepare_state

    def visitState_fail(self, ctx: LSLParser.State_failContext):
        where = self.visit(ctx.fail_where())
        state = {"Type": "Fail", **where}
        return state

    def visitFail_where(self, ctx: LSLParser.Fail_whereContext):
        where = dict()
        for child in ctx.children:
            if isinstance(child, ParserRuleContext) and child.getRuleIndex() in {
                LSLParser.RULE_error,
                LSLParser.RULE_cause,
            }:
                key, value = self.visit(child)
                where[key] = value
        return where

    def visitError(self, ctx: LSLParser.ErrorContext):
        error_expr = self.visit(ctx.string_or_jsonata())
        return "Error", error_expr

    def visitCause(self, ctx: LSLParser.CauseContext):
        cause_expr = self.visit(ctx.string_or_jsonata())
        return "Cause", cause_expr

    def visitState_task(self, ctx: LSLParser.State_taskContext):
        service_name = self.visitService_name(ctx.service_name())
        action_name = from_string_literal(ctx.IDEN())
        where = self.visitTask_where(ctx.task_where())
        state = {
            "Type": "Task",
            # TODO: add support for aws-sdk, and callbacks
            "Resource": f"arn:aws:states:::{service_name}:{action_name}",
            "End": True,
            **where,
        }
        return state

    def visitService_name(self, ctx: LSLParser.Service_nameContext):
        service_name = from_string_literal(ctx.children[0])
        return service_name

    def visitTask_where(self, ctx: LSLParser.Task_whereContext):
        where = dict()
        for child in ctx.children:
            if isinstance(child, ParserRuleContext) and child.getRuleIndex() in {
                LSLParser.RULE_arguments,
                LSLParser.RULE_catch_block,
            }:
                key, value = self.visit(child)
                where[key] = value
        return where

    def new_inner_scope(self):
        scope = _Scope(self._this_scope())
        self._scopes.append(scope)
        return scope

    def close_scope(self):
        self._scopes.pop()

    def visitState_parallel(self, ctx: LSLParser.State_parallelContext):
        branches = list()
        for child in ctx.children:
            if (
                isinstance(child, ParserRuleContext)
                and child.getRuleIndex() == LSLParser.RULE_process
            ):
                scope = self.new_inner_scope()
                self.visit(child)
                self.close_scope()
                workflow = scope.to_scope_workflow()
                branches.append(workflow)
        state = {"Type": "Parallel", "End": True, "Branches": [*branches]}
        return state

    def visitState_map(self, ctx: LSLParser.State_mapContext):
        scope = self.new_inner_scope()
        items_var_name = from_string_literal(ctx.IDEN())
        input_state_name = f"map:process:{ctx.start.line}:{ctx.start.column}:input"
        input_state = {
            "Type": "Pass",
            "Assign": {items_var_name: "{% $states.input %}"},
            "End": True,
        }
        scope.set_next(state_name=input_state_name, state=input_state)
        self.visit(ctx.process())
        self.close_scope()
        inner_workflow = scope.to_scope_workflow()

        items_expression = self.visit(ctx.json_value())
        state = {
            "Type": "Map",
            "End": True,
            "Items": items_expression,
            "MaxConcurrency": 1,
            "ItemProcessor": {"ProcessorConfig": {"Mode": "INLINE"}, **inner_workflow},
        }
        return state

    def visitProcess(self, ctx: LSLParser.ProcessContext):
        expressions = list()
        for child in ctx.children:
            if isinstance(child, ParserRuleContext) and child.getRuleIndex() in {
                LSLParser.RULE_state_call,
                LSLParser.RULE_state_declaration,
                LSLParser.RULE_var_assign,
            }:
                expression = self.visit(child)
                expressions.append(expression)
        return expressions

    def visitArguments(self, ctx: LSLParser.ArgumentsContext):
        value = self.visit(ctx.json_value())
        return "Arguments", value

    def visitVar_assign_json_value(self, ctx: LSLParser.Var_assign_json_valueContext):
        variable_name = from_string_literal(ctx.IDEN())
        value_expression = self.visit(ctx.json_value())

        state_name = f"assign:{ctx.start.line}:{ctx.start.column}"
        state = {"Type": "Pass", "Assign": {variable_name: value_expression}, "End": True}

        scope = self._this_scope()
        scope.set_next(state_name=state_name, state=state)

        return state

    def visitVar_assign_state_call(self, ctx: LSLParser.Var_assign_state_callContext):
        super().visit(ctx.state_call())

        variable_name = from_string_literal(ctx.IDEN())

        state_name = f"assign:{ctx.start.line}:{ctx.start.column}"
        state = {"Type": "Pass", "Assign": {variable_name: "{% $states.input %}"}, "End": True}

        scope = self._this_scope()
        scope.set_next(state_name=state_name, state=state)

        return state

    def visitJson_value_int(self, ctx: LSLParser.Json_value_intContext):
        return int(ctx.INT().getText())

    def visitJson_value_float(self, ctx: LSLParser.Json_value_floatContext):
        return float(ctx.NUMBER().getText())

    def visitJson_value_bool(self, ctx: LSLParser.Json_value_boolContext):
        bool_child = ctx.children[0]
        bool_term_rule: int = bool_child.getSymbol().type
        bool_val: bool = bool_term_rule == LSLLexer.TRUE
        return bool_val

    def visitJson_value_null(self, ctx: LSLParser.Json_value_nullContext):
        return None

    def visitJson_binding(self, ctx: LSLParser.Json_bindingContext):
        key = from_string_literal(ctx.children[0])
        value = self.visit(ctx.json_value())
        return key, value

    def visitJson_value_str(self, ctx: LSLParser.Json_value_strContext):
        string = from_string_literal(ctx.STRING())
        return string

    def visitJson_value_jsonata(self, ctx: LSLParser.Json_value_jsonataContext):
        jsonata_expression = ctx.JSONATA().getText()[len("jsonata(") : -1]
        return "{% " + jsonata_expression + " %}"

    def visitJson_object(self, ctx: LSLParser.Json_objectContext):
        o = dict()
        for child in ctx.children:
            if (
                isinstance(child, ParserRuleContext)
                and child.getRuleIndex() == LSLParser.RULE_json_binding
            ):
                key, value = self.visitJson_binding(ctx=child)  # noqa
                o[key] = value
        return o

    def visitJson_arr(self, ctx: LSLParser.Json_arrContext):
        arr = list()
        for child in ctx.children:
            if isinstance(child, ParserRuleContext):
                value = self.visit(child)
                arr.append(value)
        return arr

    def visitString_or_jsonata_string(self, ctx: LSLParser.String_or_jsonata_stringContext):
        string = from_string_literal(ctx.STRING())
        return string

    def visitString_or_jsonata_jsonata(self, ctx: LSLParser.String_or_jsonata_jsonataContext):
        jsonata_expression = ctx.JSONATA().getText()[len("jsonata(") : -1]
        return "{% " + jsonata_expression + " %}"
