from __future__ import annotations

from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.jsonata.jsonata import (
    VariableDeclarations,
    encode_jsonata_variable_declarations,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

VariableIdentifier = str
VariableValue = Any


class VariableStoreError(RuntimeError):
    message: Final[str]

    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return f"{self.__class__.__name__} {self.message}"

    def __repr__(self):
        return str(self)


class NoSuchVariable(VariableStoreError):
    variable_identifier: Final[VariableIdentifier]

    def __init__(self, variable_identifier: VariableIdentifier):
        super().__init__(message=f"No such variable '{variable_identifier}' in scope")
        self.variable_identifier = variable_identifier


class IllegalOuterScopeWrite(VariableStoreError):
    variable_identifier: Final[VariableIdentifier]
    variable_value: Final[VariableValue]

    def __init__(self, variable_identifier: VariableIdentifier, variable_value: VariableValue):
        super().__init__(
            message=f"Cannot bind value '{variable_value}' to variable '{variable_identifier}' as it belongs to an outer scope."
        )
        self.variable_identifier = variable_identifier
        self.variable_value = variable_value


class VariableStore:
    _outer_scope: Final[dict]
    _inner_scope: Final[dict]

    _declaration_tracing: Final[set[str]]

    _outer_variable_declaration_cache: Optional[VariableDeclarations]
    _variable_declarations_cache: Optional[VariableDeclarations]

    def __init__(self):
        self._outer_scope = dict()
        self._inner_scope = dict()
        self._declaration_tracing = set()
        self._outer_variable_declaration_cache = None
        self._variable_declarations_cache = None

    @classmethod
    def as_inner_scope_of(cls, outer_variable_store: VariableStore) -> VariableStore:
        inner_variable_store = cls()
        inner_variable_store._outer_scope.update(outer_variable_store._outer_scope)
        inner_variable_store._outer_scope.update(outer_variable_store._inner_scope)
        return inner_variable_store

    def reset_tracing(self) -> None:
        self._declaration_tracing.clear()

    # TODO: add typing when this available in service init.
    def get_assigned_variables(self) -> dict[str, str]:
        assigned_variables: dict[str, str] = dict()
        for traced_declaration_identifier in self._declaration_tracing:
            traced_declaration_value = self.get(traced_declaration_identifier)
            if isinstance(traced_declaration_value, str):
                traced_declaration_value_json_str = f'"{traced_declaration_value}"'
            else:
                traced_declaration_value_json_str: str = to_json_str(
                    traced_declaration_value, separators=(",", ":")
                )
            assigned_variables[traced_declaration_identifier] = traced_declaration_value_json_str
        return assigned_variables

    def get(self, variable_identifier: VariableIdentifier) -> VariableValue:
        if variable_identifier in self._inner_scope:
            return self._inner_scope[variable_identifier]
        if variable_identifier in self._outer_scope:
            return self._outer_scope[variable_identifier]
        raise NoSuchVariable(variable_identifier=variable_identifier)

    def set(self, variable_identifier: VariableIdentifier, variable_value: VariableValue) -> None:
        if variable_identifier in self._outer_scope:
            raise IllegalOuterScopeWrite(
                variable_identifier=variable_identifier, variable_value=variable_value
            )
        self._declaration_tracing.add(variable_identifier)
        self._inner_scope[variable_identifier] = variable_value
        self._variable_declarations_cache = None

    @staticmethod
    def _to_variable_declarations(bindings: dict[str, Any]) -> VariableDeclarations:
        variables = {f"${key}": value for key, value in bindings.items()}
        encoded = encode_jsonata_variable_declarations(variables)
        return encoded

    def get_variable_declarations(self) -> VariableDeclarations:
        if self._variable_declarations_cache is not None:
            return self._variable_declarations_cache
        if self._outer_variable_declaration_cache is None:
            self._outer_variable_declaration_cache = self._to_variable_declarations(
                self._outer_scope
            )
        inner_variable_declarations_cache = self._to_variable_declarations(self._inner_scope)
        self._variable_declarations_cache = "".join(
            [self._outer_variable_declaration_cache, inner_variable_declarations_cache]
        )
        return self._variable_declarations_cache
