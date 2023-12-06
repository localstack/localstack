import os

from moto.redshift import responses as redshift_responses
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
from localstack.utils.common import recurse_object
from localstack.utils.patch import patch


@patch(redshift_responses.itemize)
def itemize(fn, data, parent_key=None, *args, **kwargs):
    # TODO: potentially add additional required tags here!
    list_parent_tags = ["ClusterSubnetGroups"]

    def fix_keys(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in list_parent_tags:
                    if isinstance(v, dict) and "item" in v:
                        v[k[:-1]] = v.pop("item")
        return o

    result = fn(data, *args, **kwargs)
    recurse_object(result, fix_keys)
    return result


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
