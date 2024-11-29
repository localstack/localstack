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
        analyser.analyse(definition=definition)

        try:
            if analyser.has_jsonata:
                UsageMetrics.jsonata_create_counter.increment()
            else:
                UsageMetrics.jsonpath_create_counter.increment()
        except Exception as e:
            LOG.warning(
                "Failed to record metrics for StepFunctions QueryLanguage usage",
                exc_info=e,
            )

        try:
            if analyser.has_variable_sampling:
                UsageMetrics.variables_create_counter.increment()
        except Exception as e:
            LOG.warning(
                "Failed to record usage metrics for StepFunctions Variable Sampling usage",
                exc_info=e,
            )

        return analyser

    def __init__(self):
        super().__init__()
        self.has_jsonata: bool = False
        self.has_variable_sampling = False

    def visitQuery_language_decl(self, ctx: ASLParser.Query_language_declContext):
        query_language_mode_int = ctx.children[-1].getSymbol().type
        query_language_mode = QueryLanguageMode(value=query_language_mode_int)
        if query_language_mode == QueryLanguageMode.JSONata:
            self.has_jsonata = True

    def visitVariable_sample(self, ctx: ASLParser.Variable_sampleContext):
        self.has_variable_sampling = True

    def visitAssign_decl(self, ctx: ASLParser.Assign_declContext):
        self.has_variable_sampling = True
