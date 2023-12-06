from types import ModuleType

import pytest
from click.testing import CliRunner

from localstack.aws.scaffold import generate
from localstack.testing.pytest import markers


@markers.skip_offline
@pytest.mark.parametrize(
    "service",
    [
        "apigateway",
        "autoscaling",
        "cloudformation",
        "dynamodb",
        "glue",
        "kafka",
        "kinesis",
        "sqs",
        "s3",
    ],
)
def test_generated_code_compiles(service, caplog):
    # Deactivate logging on CLI (https://github.com/pallets/click/issues/824#issuecomment-562581313)
    caplog.set_level(100000)

    runner = CliRunner()
    result = runner.invoke(generate, [service, "--no-doc", "--print"])
    assert result.exit_code == 0

    # Get the generated code
    code = result.output

    # Make sure the code is compilable
    compiled = compile(code, "<string>", "exec")

    # Make sure the code is importable
    # (f.e. Kafka contains types with double underscores in the spec, which would result in an import error)
    module = ModuleType(service)
    exec(compiled, module.__dict__)
