import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestOpenSearchPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_domain_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        opensearch_client = aws_client_factory(region_name=region).opensearch

        domain_name = f"opensearch-domain-{short_uid()}"
        domain_arn = opensearch_client.create_domain(DomainName=domain_name)["DomainStatus"]["ARN"]
        assert domain_arn == f"arn:{partition}:es:{region}:{account_id}:domain/{domain_name}"
