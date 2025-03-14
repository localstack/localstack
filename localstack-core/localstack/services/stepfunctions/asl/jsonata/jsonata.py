from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Final, Optional

import jpype
import jpype.imports

from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.packages import jpype_jsonata_package
from localstack.utils.objects import singleton_factory

JSONataExpression = str
VariableReference = str
VariableDeclarations = str

_PATTERN_VARIABLE_REFERENCE: Final[re.Pattern] = re.compile(
    r"\$\$|\$[a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_][a-zA-Z0-9_$]*)*|\$"
)
_ILLEGAL_VARIABLE_REFERENCES: Final[set[str]] = {"$", "$$"}
_VARIABLE_REFERENCE_ASSIGNMENT_OPERATOR: Final[str] = ":="
_VARIABLE_REFERENCE_ASSIGNMENT_STOP_SYMBOL: Final[str] = ";"
_EXPRESSION_OPEN_SYMBOL: Final[str] = "("
_EXPRESSION_CLOSE_SYMBOL: Final[str] = ")"


class JSONataException(Exception):
    error: Final[str]
    details: Optional[str]

    def __init__(self, error: str, details: Optional[str]):
        self.error = error
        self.details = details


class _JSONataJVMBridge:
    _java_OBJECT_MAPPER: "com.fasterxml.jackson.databind.ObjectMapper"  # noqa
    _java_JSONATA: "com.dashjoin.jsonata.Jsonata.jsonata"  # noqa

    def __init__(self):
        installer = jpype_jsonata_package.get_installer()
        installer.install()

        from jpype import config as jpype_config

        jpype_config.destroy_jvm = False

        # Limitation: We can only start one JVM instance within LocalStack and using JPype for another purpose
        # (e.g., event-ruler) fails unless we change the way we load/reload the classpath.
        jvm_path = installer.get_java_lib_path()
        jsonata_libs_path = Path(installer.get_installed_dir())
        jsonata_libs_pattern = jsonata_libs_path.joinpath("*")
        jpype.startJVM(jvm_path, classpath=[jsonata_libs_pattern], interrupt=False)

        from com.fasterxml.jackson.databind import ObjectMapper  # noqa
        from com.dashjoin.jsonata.Jsonata import jsonata  # noqa

        self._java_OBJECT_MAPPER = ObjectMapper()
        self._java_JSONATA = jsonata

    @staticmethod
    @singleton_factory
    def get() -> _JSONataJVMBridge:
        return _JSONataJVMBridge()

    def eval_jsonata(self, jsonata_expression: JSONataExpression) -> Any:
        try:
            # Evaluate the JSONata expression with the JVM.
            # TODO: Investigate whether it is worth moving this chain of statements (java_*) to a
            #  Java program to reduce i/o between the JVM and this runtime.
            java_expression = self._java_JSONATA(jsonata_expression)
            java_output = java_expression.evaluate(None)
            java_output_string = self._java_OBJECT_MAPPER.writeValueAsString(java_output)

            # Compute a Python json object from the java string, this is to:
            #  1. Ensure we fully end interactions with the JVM about this value here;
            #  2. The output object may undergo under operations that are not compatible
            #     with jpype objects (such as json.dumps, equality, instanceof, etc.).
            result_str: str = str(java_output_string)
            result_json = json.loads(result_str)

            return result_json
        except Exception as ex:
            raise JSONataException("UNKNOWN", str(ex))


# Lazy initialization of the `eval_jsonata` function pointer.
# This ensures the JVM is only started when JSONata functionality is needed.
_eval_jsonata: Optional[Callable[[JSONataExpression], Any]] = None


def eval_jsonata_expression(jsonata_expression: JSONataExpression) -> Any:
    global _eval_jsonata
    if _eval_jsonata is None:
        # Initialize _eval_jsonata only when invoked for the first time using the Singleton pattern.
        _eval_jsonata = _JSONataJVMBridge.get().eval_jsonata
    return _eval_jsonata(jsonata_expression)


class IllegalJSONataVariableReference(ValueError):
    variable_reference: Final[VariableReference]

    def __init__(self, variable_reference: VariableReference):
        self.variable_reference = variable_reference


def extract_jsonata_variable_references(
    jsonata_expression: JSONataExpression,
) -> set[VariableReference]:
    if not jsonata_expression:
        return set()
    variable_references: list[VariableReference] = _PATTERN_VARIABLE_REFERENCE.findall(
        jsonata_expression
    )
    for variable_reference in variable_references:
        if variable_reference in _ILLEGAL_VARIABLE_REFERENCES:
            raise IllegalJSONataVariableReference(variable_reference=variable_reference)
    return set(variable_references)


def encode_jsonata_variable_declarations(
    bindings: dict[VariableReference, Any],
) -> VariableDeclarations:
    declarations_parts: list[str] = list()
    for variable_reference, value in bindings.items():
        if isinstance(value, str):
            value_str_lit = f'"{value}"'
        else:
            value_str_lit = to_json_str(value, separators=(",", ":"))
        declarations_parts.extend(
            [
                variable_reference,
                _VARIABLE_REFERENCE_ASSIGNMENT_OPERATOR,
                value_str_lit,
                _VARIABLE_REFERENCE_ASSIGNMENT_STOP_SYMBOL,
            ]
        )
    return "".join(declarations_parts)


def compose_jsonata_expression(
    final_jsonata_expression: JSONataExpression,
    variable_declarations_list: list[VariableDeclarations],
) -> JSONataExpression:
    variable_declarations = "".join(variable_declarations_list)
    expression = "".join(
        [
            _EXPRESSION_OPEN_SYMBOL,
            variable_declarations,
            final_jsonata_expression,
            _EXPRESSION_CLOSE_SYMBOL,
        ]
    )
    return expression
