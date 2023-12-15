import abc

from localstack.services.stepfunctions.asl.antlr.runtime.ASLParserVisitor import ASLParserVisitor


class StaticAnalyser(ASLParserVisitor, abc.ABC):
    def analyse(self, program_tree) -> None:
        program = self.visit(program_tree)
        return program
