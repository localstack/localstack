import os

from moto.redshift.models import redshift_backends

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.redshift import (
    ClusterSecurityGroupMessage,
    DescribeClusterSecurityGroupsMessage,
    RedshiftApi,
)
from localstack.services.moto import call_moto
from localstack.state import AssetDirectory, StateVisitor


class RedshiftProvider(RedshiftApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(redshift_backends)
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, "redshift")))

    @handler("DescribeClusterSecurityGroups", expand=False)
    def describe_cluster_security_groups(
        self,
        context: RequestContext,
        request: DescribeClusterSecurityGroupsMessage,
    ) -> ClusterSecurityGroupMessage:
        result = call_moto(context)
        backend = redshift_backends[context.account_id][context.region]
        for group in result.get("ClusterSecurityGroups", []):
            if group.get("IPRanges"):
                continue
            sgroup = backend.security_groups.get(group["ClusterSecurityGroupName"])
            group["IPRanges"] = [
                {"Status": "authorized", "CIDRIP": ip} for ip in sgroup.ingress_rules
            ]
        return result
