"""Exceptions for lambda event source mapping machinery."""


class FunctionNotFoundError(Exception):
    """Indicates that a function that is part of an existing event source listener does not exist."""
