import typing as t
from gettext import gettext

import click
from click import ClickException, echo
from click._compat import get_text_stderr


class CLIError(ClickException):
    """A ClickException with a red error message"""

    def format_message(self) -> str:
        return click.style(f"❌ Error: {self.message}", fg="red")

    def show(self, file: t.Optional[t.IO[t.Any]] = None) -> None:
        if file is None:
            file = get_text_stderr()

        echo(gettext(self.format_message()), file=file)
