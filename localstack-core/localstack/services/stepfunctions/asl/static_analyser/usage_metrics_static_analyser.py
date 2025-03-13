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
            query_modes = analyser._query_language_modes
            if len(query_modes) == 2:
                language_used = QueryLanguage.Both
            elif QueryLanguageMode.JSONata in query_modes:
                language_used = QueryLanguage.JSONata
            else:
                language_used = QueryLanguage.JSONPath

            # Determine is the state machine uses the variables feature.
            uses_variables = analyser._uses_variables

            # Count.
            UsageMetrics.language_features_counter.labels(
                query_language=language_used, variables=uses_variables
            ).increment()
        except Exception as e:
            LOG.warning(
                "Failed to record Step Functions metrics from static analysis",
                exc_info=e,
            )
        return analyser

    _query_language_modes: Final[set[QueryLanguageMode]]
    _uses_variables: bool

    def __init__(self):
        super().__init__()
        self._query_language_modes = set()
        self._uses_variables = False

    def visitQuery_language_decl(self, ctx: ASLParser.Query_language_declContext):
        if len(self._query_language_modes) == 2:
            # Both query language modes have been confirmed to be in use.
            return
        query_language_mode_int = ctx.children[-1].getSymbol().type
        query_language_mode = QueryLanguageMode(value=query_language_mode_int)
        self._query_language_modes.add(query_language_mode)

    def visitString_literal(self, ctx: ASLParser.String_literalContext):
        # Prune everything parsed as a string literal.
        return

    def visitString_variable_sample(self, ctx: ASLParser.String_variable_sampleContext):
        self._uses_variables = True

    def visitAssign_decl(self, ctx: ASLParser.Assign_declContext):
        self._uses_variables = True
