from .console import console
from .plugin import LocalstackCli, LocalstackCliPlugin

name = "cli"

__all__ = [
    "console",
    "LocalstackCli",
    "LocalstackCliPlugin",
]
