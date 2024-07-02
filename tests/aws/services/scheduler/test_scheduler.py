import pytest

from localstack.testing.aws.util import in_default_partition
from localstack.testing.pytest import markers


@pytest.mark.skipif(
    not in_default_partition(), reason="Test not applicable in non-default partitions"
)
@markers.aws.validated
def test_list_schedules(aws_client):
    # simple smoke test to assert that the provider is available, without creating any schedules
    result = aws_client.scheduler.list_schedules()
    assert isinstance(result.get("Schedules"), list)
