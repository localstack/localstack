import json
import os

import click

from localstack.services.stepfunctions.asl.lsl.transpiler import transpile


@click.command()
@click.argument(
    "input_file", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=str)
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True, path_type=str),
    help="Path to output JSON file.",
)
def cli(input_file: str, output: str):
    """Transpile an LSL derivation file to JSON."""
    with open(input_file, "r") as f:
        content = f.read()

    result = transpile(content)

    output_file = output or os.path.splitext(input_file)[0] + ".asl.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    click.echo(f"Transpiled successfully to {output_file}")


if __name__ == "__main__":
    cli()
