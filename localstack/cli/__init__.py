from .console import console
from .localstack import create_with_plugins
from .plugin import LocalstackCli, LocalstackCliPlugin

name = "cli"

__all__ = [
    "console",
    "create_with_plugins",
    "LocalstackCli",
    "LocalstackCliPlugin",
]
