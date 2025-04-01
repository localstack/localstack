from __future__ import annotations

import logging
from typing import Final

import localstack.services.stepfunctions.usage as UsageMetrics
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser

LOG = logging.getLogger(__name__)


class QueryLanguage(str):
    JSONPath = QueryLanguageMode.JSONPath.name
    JSONata = QueryLanguageMode.JSONata.name
    Both = "JSONPath+JSONata"


class UsageMetricsStaticAnalyser(StaticAnalyser):
    @staticmethod
    def process(definition: str) -> UsageMetricsStaticAnalyser:
        analyser = UsageMetricsStaticAnalyser()
        try:
            # Run the static analyser.
            analyser.analyse(definition=definition)

            # Determine which query language is being used in this state machine.
            query_modes = analyser.query_language_modes
            if len(query_modes) == 2:
                language_used = QueryLanguage.Both
            elif QueryLanguageMode.JSONata in query_modes:
                language_used = QueryLanguage.JSONata
            else:
                language_used = QueryLanguage.JSONPath

            # Determine is the state machine uses the variables feature.
            uses_variables = analyser.uses_variables

            # Count.
            UsageMetrics.language_features_counter.labels(
                query_language=language_used, uses_variables=uses_variables
            ).increment()
        except Exception as e:
            LOG.warning(
                "Failed to record Step Functions metrics from static analysis",
                exc_info=e,
            )
        return analyser

    query_language_modes: Final[set[QueryLanguageMode]]
    uses_variables: bool

    def __init__(self):
        super().__init__()
        self.query_language_modes = set()
        self.uses_variables = False

    def visitQuery_language_decl(self, ctx: ASLParser.Query_language_declContext):
        if len(self.query_language_modes) == 2:
            # Both query language modes have been confirmed to be in use.
            return
        query_language_mode_int = ctx.children[-1].getSymbol().type
        query_language_mode = QueryLanguageMode(value=query_language_mode_int)
        self.query_language_modes.add(query_language_mode)

    def visitState_decl(self, ctx: ASLParser.State_declContext):
        # If before entering a state, no query language was explicitly enforced, then we know
        # this is the first state operating under the default mode (JSONPath)
        if not self.query_language_modes:
            self.query_language_modes.add(QueryLanguageMode.JSONPath)
        super().visitState_decl(ctx=ctx)

    def visitString_literal(self, ctx: ASLParser.String_literalContext):
        # Prune everything parsed as a string literal.
        return

    def visitString_variable_sample(self, ctx: ASLParser.String_variable_sampleContext):
        self.uses_variables = True

    def visitAssign_decl(self, ctx: ASLParser.Assign_declContext):
        self.uses_variables = True
