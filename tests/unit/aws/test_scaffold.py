import pytest
from click.testing import CliRunner

from localstack.aws.scaffold import generate


@pytest.mark.skip_offline
@pytest.mark.parametrize(
    "service", ["apigateway", "autoscaling", "cloudformation", "dynamodb", "sqs"]
)
def test_generated_code_compiles(service):
    runner = CliRunner()
    result = runner.invoke(generate, [service, "--no-doc", "--print"])
    assert result.exit_code == 0
    code = result.output
    compile(code, "<string>", "exec")
