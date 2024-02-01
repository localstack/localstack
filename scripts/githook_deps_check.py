"""
Git hook that checks if there's been any updates to a set of predefined files

This is for example useful to be alerted if there might be a need to reinstall the project
"""

import os
import subprocess

from rich.console import Console

c = Console()

DISABLE_CHECKS_ENV_VAR = "GITHOOK_DISABLE_DEPS_CHECK"

# basically anything that might lead to issues with an existing local setup
files_to_watch = ["setup.py", "setup.cfg", "requirements.txt", "Makefile", "pyproject.toml"]

# TODO: alert on rebase
# TODO: alert on pull
# TODO: compare providers
# TODO: compare plugins


if __name__ == "__main__":
    if os.environ.get(DISABLE_CHECKS_ENV_VAR, "0") == "1":
        exit(0)

    envs = {k: v for k, v in os.environ.items() if k.startswith("PRE_COMMIT")}

    # checkout
    from_commit = envs.get("PRE_COMMIT_FROM_REF")
    to_commit = envs.get("PRE_COMMIT_TO_REF")

    if from_commit and to_commit:
        r = subprocess.run(
            ["git", "diff", "--name-only", from_commit, to_commit], capture_output=True
        )

        files = r.stdout.decode().splitlines()

        for file in files_to_watch:
            if file in files:
                c.print(
                    f"[red]ATTENTION![/red] Found a change in file [red]{file}[/red] during the checkout."
                )
                c.print(
                    f"\t>> show changes: [bold]git diff {from_commit[:8]}:{file} {to_commit[:8]}:{file}[/bold]\n"
                )
