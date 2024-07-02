import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestRoute53ResolverPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition", [("us-east-2", "aws"), ("us-gov-east-1", "aws-us-gov")]
    )
    def test_query_log_config_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        logs = aws_client_factory(region_name=region).logs
        route53_resolver = aws_client_factory(region_name=region).route53resolver

        log_group_name = f"test-r53resolver-lg-{short_uid()}"
        logs.create_log_group(logGroupName=log_group_name)
        lg_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

        query_log_config_arn = route53_resolver.create_resolver_query_log_config(
            Name=f"test-{short_uid()}",
            DestinationArn=lg_arn,
            CreatorRequestId=short_uid(),
        )["ResolverQueryLogConfig"]["Arn"]
        assert query_log_config_arn.startswith(
            f"arn:{partition}:route53resolver:{region}:{account_id}:resolver-query-log-config/"
        )
