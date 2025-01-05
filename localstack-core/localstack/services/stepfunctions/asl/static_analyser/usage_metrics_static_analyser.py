import logging

import localstack.services.stepfunctions.usage as UsageMetrics
from localstack.services.stepfunctions.asl.antlr.runtime.ASLParser import ASLParser
from localstack.services.stepfunctions.asl.component.common.query_language import (
    QueryLanguageMode,
)
from localstack.services.stepfunctions.asl.static_analyser.static_analyser import StaticAnalyser

LOG = logging.getLogger(__name__)


class UsageMetricsStaticAnalyser(StaticAnalyser):
    @staticmethod
    def process(definition: str) -> "UsageMetricsStaticAnalyser":
        analyser = UsageMetricsStaticAnalyser()
        try:
            analyser.analyse(definition=definition)

            if analyser.has_jsonata:
                UsageMetrics.jsonata_create_counter.increment()
            else:
                UsageMetrics.jsonpath_create_counter.increment()

            if analyser.has_variable_sampling:
                UsageMetrics.variables_create_counter.increment()
        except Exception as e:
            LOG.warning(
                "Failed to record Step Functions metrics from static analysis",
                exc_info=e,
            )
        return analyser

    def __init__(self):
        super().__init__()
        self.has_jsonata: bool = False
        self.has_variable_sampling = False

    def visitQuery_language_decl(self, ctx: ASLParser.Query_language_declContext):
        if self.has_jsonata:
            return

        query_language_mode_int = ctx.children[-1].getSymbol().type
        query_language_mode = QueryLanguageMode(value=query_language_mode_int)
        if query_language_mode == QueryLanguageMode.JSONata:
            self.has_jsonata = True

    def visitString_literal(self, ctx: ASLParser.String_literalContext):
        # Prune everything parsed as a string literal.
        return

    def visitString_variable_sample(self, ctx: ASLParser.String_variable_sampleContext):
        self.has_variable_sampling = True

    def visitAssign_decl(self, ctx: ASLParser.Assign_declContext):
        self.has_variable_sampling = True
