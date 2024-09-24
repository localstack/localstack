import logging
import re

import pytest

from localstack.aws.api.route53resolver import (
    ListResolverEndpointsResponse,
    ListResolverQueryLogConfigsResponse,
    ListResolverRuleAssociationsResponse,
)
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.functions import call_safe
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def route53resolver_api_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.route53resolver_api())


# TODO: extract this somewhere so that we can reuse it in other places
def _cleanup_vpc(aws_client: ServiceLevelClientFactory, vpc_id: str):
    """
    perform a safe cleanup of a VPC
    this method assumes that any existing network interfaces have already been detached
    """
    # delete security groups
    sgs = aws_client.ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for sg in sgs["SecurityGroups"]:
        if sg["GroupName"] != "default":  # default security group can't be deleted
            call_safe(lambda: aws_client.ec2.delete_security_group(GroupId=sg["GroupId"]))

    # delete subnets
    subnets = aws_client.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for subnet in subnets["Subnets"]:
        call_safe(lambda: aws_client.ec2.delete_subnet(SubnetId=subnet["SubnetId"]))

    # finally, delete the vpc
    aws_client.ec2.delete_vpc(VpcId=vpc_id)


def delete_route53_resolver_endpoint(route53resolver_client, resolver_endpoint_id: str):
    """delete a route53resolver resolver endpoint and wait until it is actually deleted"""

    def _delete_resolver_endpoint():
        # deleting a resolver endpoint is an async operation, but we can't properly observe it since there's no "deleted" terminal state
        route53resolver_client.delete_resolver_endpoint(ResolverEndpointId=resolver_endpoint_id)

        # retry until we can't get it anymore
        def _is_endpoint_deleted():
            try:
                route53resolver_client.get_resolver_endpoint(
                    ResolverEndpointId=resolver_endpoint_id
                )
            except Exception:
                return True
            else:
                return False

        poll_condition(_is_endpoint_deleted, timeout=180, interval=3 if is_aws_cloud() else 1)

    return _delete_resolver_endpoint


@markers.snapshot.skip_snapshot_verify(paths=["$..ResolverEndpointType"])
class TestRoute53Resolver:
    # TODO: make this class level?
    @pytest.fixture(scope="function")
    def setup_resources(self, aws_client, cleanups):
        vpc = aws_client.ec2.create_vpc(CidrBlock="10.78.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        cleanups.append(lambda: _cleanup_vpc(aws_client, vpc_id))

        subnet1 = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.78.1.0/24")
        subnet2 = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.78.2.0/24")

        security_group = aws_client.ec2.create_security_group(
            GroupName=f"test-sg-{short_uid()}", VpcId=vpc_id, Description="test sg"
        )

        yield vpc, subnet1, subnet2, security_group

    def _construct_ip_for_cidr_and_host(self, cidr_block: str, host_id: str) -> str:
        return re.sub(r"(.*)\.[0-9]+/.+", r"\1." + host_id, cidr_block)

    @staticmethod
    def _wait_associate_or_disassociate_resolver_rule(client, resolver_rule_id, vpc_id, action):
        def _is_resolver_rule_disassociated(lst):
            for rra in lst.get("ResolverRuleAssociations", []):
                if rra["ResolverRuleId"] == resolver_rule_id and rra["VPCId"] == vpc_id:
                    return False
            return True

        def _is_resolver_rule_associated(lst):
            for rra in lst.get("ResolverRuleAssociations", []):
                if (
                    rra["ResolverRuleId"] == resolver_rule_id
                    and rra["VPCId"] == vpc_id
                    and rra["Status"] == "COMPLETE"
                ):
                    return True
            return False

        def _list_resolver_rule_associations():
            lst: ListResolverRuleAssociationsResponse = client.list_resolver_rule_associations()
            if action == "disassociate":
                return _is_resolver_rule_disassociated(lst)
            elif action == "associate":
                return _is_resolver_rule_associated(lst)

        if not poll_condition(condition=_list_resolver_rule_associations, timeout=180, interval=2):
            LOG.warning(
                "Timed out while awaiting for resolver rule to '%s' with with VPCId:'%s' and ResolverRuleId: '%s'.",
                action,
                vpc_id,
                resolver_rule_id,
            )
        else:
            return True

    @staticmethod
    def _wait_created_log_config_is_listed_with_status(client, id, status):
        def _is_req_id_in_list():
            lst: ListResolverQueryLogConfigsResponse = client.list_resolver_query_log_configs()
            rqlc_ids_status = {}
            for rqlc in lst.get("ResolverQueryLogConfigs", []):
                rqlc_ids_status[rqlc["Id"]] = rqlc["Status"]
            for key, value in rqlc_ids_status.items():
                if key == id:
                    return value == status
            return False

        if not poll_condition(condition=_is_req_id_in_list, timeout=120, interval=2):
            LOG.warning(
                "Timed out while awaiting for resolver query log config with with id:'%s' to become listable.",
                id,
            )
        else:
            return True

    @staticmethod
    def _wait_created_endpoint_is_listed_with_status(client, req_id, status):
        def _is_req_id_in_list():
            lst: ListResolverEndpointsResponse = client.list_resolver_endpoints()
            resolver_endpoint_request_ids_status = {}

            for resolver_endpoint in lst.get("ResolverEndpoints", []):
                resolver_endpoint_request_ids_status[resolver_endpoint["CreatorRequestId"]] = (
                    resolver_endpoint["Status"]
                )
            for key, value in resolver_endpoint_request_ids_status.items():
                if key == req_id:
                    return value == status
            return False

        if not poll_condition(condition=_is_req_id_in_list, timeout=180, interval=2):
            LOG.warning(
                "Timed out while awaiting for resolver endpoint with with request id:'%s' to become listable.",
                req_id,
            )
        else:
            return True

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    @pytest.mark.parametrize(
        "direction, hostId",
        [
            ("INBOUND", "5"),
            ("OUTBOUND", "10"),
        ],
    )
    def test_create_resolver_endpoint(
        self, direction, hostId, cleanups, snapshot, aws_client, setup_resources
    ):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]

        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], hostId)
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], hostId)

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        create_resolver_endpoint_res = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction=direction,
            Name=resolver_endpoint_name,
            IpAddresses=[
                {"SubnetId": subnet1_id, "Ip": ip1},
                {"SubnetId": subnet2_id, "Ip": ip2},
            ],
        )
        resolver_endpoint = create_resolver_endpoint_res["ResolverEndpoint"]
        cleanups.append(
            delete_route53_resolver_endpoint(aws_client.route53resolver, resolver_endpoint["Id"])
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

    @markers.aws.validated
    def test_route53resolver_bad_create_endpoint_security_groups(
        self, snapshot, aws_client, setup_resources
    ):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "43")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "43")

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        with pytest.raises(
            aws_client.route53resolver.exceptions.InvalidParameterException
        ) as inavlid_param_request_res:
            aws_client.route53resolver.create_resolver_endpoint(
                CreatorRequestId=request_id,
                SecurityGroupIds=["test-invalid-sg-123"],
                Direction="INBOUND",
                Name=resolver_endpoint_name,
                IpAddresses=[
                    {"SubnetId": subnet1_id, "Ip": ip1},
                    {"SubnetId": subnet2_id, "Ip": ip2},
                ],
            )
        snapshot.match("inavlid_param_request_res", inavlid_param_request_res.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_multiple_create_resolver_endpoint_with_same_req_id(
        self, cleanups, snapshot, aws_client, setup_resources
    ):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "41")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "41")

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )
        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceExistsException
        ) as res_exists_ex:
            aws_client.route53resolver.create_resolver_endpoint(
                CreatorRequestId=request_id,
                SecurityGroupIds=[security_group_id],
                Direction="INBOUND",
                Name=resolver_endpoint_name,
                IpAddresses=[
                    {"SubnetId": subnet1_id, "Ip": ip1},
                    {"SubnetId": subnet2_id, "Ip": ip2},
                ],
            )

        snapshot.match(
            "res_exists_ex_error_code", res_exists_ex.value.response.get("Error", {}).get("Code")
        )
        snapshot.match(
            "res_exists_ex_http_status_code",
            res_exists_ex.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_update_resolver_endpoint(self, cleanups, snapshot, aws_client, setup_resources):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "58")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "58")

        request_id = short_uid()
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="INBOUND",
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )
        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        # update resolver endpoint
        update_resolver_endpoint_res = aws_client.route53resolver.update_resolver_endpoint(
            ResolverEndpointId=create_resolver_endpoint_res["Id"], Name="resolver_endpoint_name"
        )

        if self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        ):
            update_resolver_endpoint_res["Status"] = "OPERATIONAL"
        snapshot.match("update_resolver_endpoint_res", update_resolver_endpoint_res)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_delete_resolver_endpoint(self, cleanups, snapshot, aws_client, setup_resources):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "48")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "48")

        request_id = short_uid()
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="INBOUND",
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )
        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        delete_resolver_endpoint = aws_client.route53resolver.delete_resolver_endpoint(
            ResolverEndpointId=create_resolver_endpoint_res["Id"]
        )
        snapshot.match("delete_resolver_endpoint_res", delete_resolver_endpoint)

    @markers.aws.validated
    def test_delete_non_existent_resolver_endpoint(self, snapshot, aws_client):
        resolver_endpoint_id = "rslvr-123"
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=resolver_endpoint_id
            )
        snapshot.match(
            "resource_not_found_ex_error_code",
            resource_not_found.value.response.get("Error", {}).get("Code"),
        )
        snapshot.match(
            "resource_not_found_ex_http_status_code",
            resource_not_found.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_create_resolver_rule(self, cleanups, snapshot, aws_client, setup_resources):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "38")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "38")

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )
        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        create_resolver_rule_res = aws_client.route53resolver.create_resolver_rule(
            CreatorRequestId=short_uid(),
            RuleType="FORWARD",
            DomainName="www.example1.com",
            ResolverEndpointId=create_resolver_endpoint_res["Id"],
            TargetIps=[
                {"Ip": "10.0.1.200", "Port": 123},
            ],
        )
        create_resolver_rule_res = create_resolver_rule_res.get("ResolverRule")
        snapshot.match("create_resolver_rule_res", create_resolver_rule_res)
        delete_resolver_rule_res = aws_client.route53resolver.delete_resolver_rule(
            ResolverRuleId=create_resolver_rule_res["Id"]
        )
        snapshot.match("delete_resolver_rule_res", delete_resolver_rule_res)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_create_resolver_rule_with_invalid_direction(
        self, cleanups, snapshot, aws_client, setup_resources
    ):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "28")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "28")

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        with pytest.raises(
            aws_client.route53resolver.exceptions.InvalidRequestException
        ) as inavlid_request:
            aws_client.route53resolver.create_resolver_rule(
                CreatorRequestId=short_uid(),
                RuleType="FORWARD",
                DomainName="www.example2.com",
                ResolverEndpointId=create_resolver_endpoint_res["Id"],
                TargetIps=[
                    {"Ip": "10.0.1.200", "Port": 123},
                ],
            )

        snapshot.match("invalid_request_ex", inavlid_request.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_multipe_create_resolver_rule(self, cleanups, snapshot, aws_client, setup_resources):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "18")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "18")

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )
        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        rslvr_rule_req_ids = [short_uid(), short_uid(), short_uid()]
        for ind, req_id in enumerate(rslvr_rule_req_ids):
            create_resolver_rule_res = aws_client.route53resolver.create_resolver_rule(
                CreatorRequestId=req_id,
                RuleType="FORWARD",
                DomainName=f"www.example{ind}.com",
                ResolverEndpointId=resolver_endpoint_id,
                TargetIps=[
                    {"Ip": "10.0.1.100", "Port": 123},
                ],
            )

            create_resolver_rule_res = create_resolver_rule_res.get("ResolverRule")
            resolver_rule_id = create_resolver_rule_res["Id"]
            snapshot.match(f"create_resolver_rule_res_{ind}", create_resolver_rule_res)

            delete_resolver_rule = aws_client.route53resolver.delete_resolver_rule(
                ResolverRuleId=resolver_rule_id
            )
            snapshot.match(f"delete_resolver_rule_res{ind}", delete_resolver_rule)

    @markers.aws.validated
    def test_delete_non_existent_resolver_rule(self, snapshot, aws_client):
        resolver_rule_id = "id-123"
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.delete_resolver_rule(ResolverRuleId=resolver_rule_id)
        snapshot.match("resource_not_found_res", resource_not_found.value.response)

    @markers.aws.validated
    def test_disassociate_non_existent_association(self, snapshot, aws_client):
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.disassociate_resolver_rule(
                ResolverRuleId="rslvr-123", VPCId="vpc-123"
            )
        snapshot.match("resource_not_found_res", resource_not_found)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..DestinationArn"  # arn of log group has a ":*" suffix which create_resolver_query_log_config seems to strip on AWS
        ]
    )
    @markers.aws.validated
    def test_create_resolver_query_log_config(self, cleanups, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.key_value("Name"))
        request_id = short_uid()

        log_group_name = f"test-r53resolver-lg-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))
        log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"]

        result = aws_client.route53resolver.create_resolver_query_log_config(
            Name=f"test-{short_uid()}",
            DestinationArn=log_group_arn,
            CreatorRequestId=request_id,
        )
        create_rqlc = result.get("ResolverQueryLogConfig")
        resolver_config_id = create_rqlc["Id"]
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_query_log_config(
                ResolverQueryLogConfigId=resolver_config_id
            )
        )
        if self._wait_created_log_config_is_listed_with_status(
            aws_client.route53resolver, resolver_config_id, "CREATED"
        ):
            create_rqlc["Status"] = "CREATED"

        snapshot.match("create_resolver_query_log_config_res", create_rqlc)

        delete_resolver_config = aws_client.route53resolver.delete_resolver_query_log_config(
            ResolverQueryLogConfigId=resolver_config_id
        )
        snapshot.match("delete_resolver_query_log_config_res", delete_resolver_config)

    @markers.snapshot.skip_snapshot_verify(paths=["$..Message"])
    @markers.aws.validated
    def test_delete_non_existent_resolver_query_log_config(self, snapshot, aws_client):
        resolver_rqlc_id = "test_123_doesntexist"
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.delete_resolver_query_log_config(
                ResolverQueryLogConfigId=resolver_rqlc_id,
            )
        error_msg = resource_not_found.value.response["Error"]["Message"]
        match = re.search('Trace Id: "(.+)"', error_msg)
        if match:
            trace_id = match.groups()[0]
            snapshot.add_transformer(snapshot.transform.regex(trace_id, "<trace-id>"))

        snapshot.match(
            "resource_not_found_ex",
            resource_not_found.value.response,
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..SecurityGroupIds", "$..ShareStatus", "$..StatusMessage"]
    )
    def test_associate_and_disassociate_resolver_rule(
        self, cleanups, snapshot, aws_client, setup_resources
    ):
        vpc, subnet1, subnet2, security_group = setup_resources
        subnet1_id = subnet1["Subnet"]["SubnetId"]
        subnet2_id = subnet2["Subnet"]["SubnetId"]
        security_group_id = security_group["GroupId"]
        ip1 = self._construct_ip_for_cidr_and_host(subnet1["Subnet"]["CidrBlock"], "68")
        ip2 = self._construct_ip_for_cidr_and_host(subnet2["Subnet"]["CidrBlock"], "68")

        snapshot.add_transformer(snapshot.transform.key_value("ResolverRuleId", "rslvr-rr-id"))
        snapshot.add_transformer(snapshot.transform.key_value("VPCId", "vpc-id"))
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=[security_group_id],
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=[{"SubnetId": subnet1_id, "Ip": ip1}, {"SubnetId": subnet2_id, "Ip": ip2}],
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]
        cleanups.append(
            delete_route53_resolver_endpoint(
                aws_client.route53resolver, create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        create_resolver_rule_res = aws_client.route53resolver.create_resolver_rule(
            CreatorRequestId=short_uid(),
            RuleType="FORWARD",
            DomainName="www.example4.com",
            ResolverEndpointId=resolver_endpoint_id,
            TargetIps=[
                {"Ip": "10.0.1.100", "Port": 123},
            ],
        )

        create_resolver_rule_res = create_resolver_rule_res.get("ResolverRule")
        resolver_rule_id = create_resolver_rule_res["Id"]

        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_rule(ResolverRuleId=resolver_rule_id)
        )

        snapshot.match("create_resolver_rule_res", create_resolver_rule_res)

        vpc_id = vpc["Vpc"]["VpcId"]

        associated_resolver_rule_res = aws_client.route53resolver.associate_resolver_rule(
            ResolverRuleId=resolver_rule_id,
            Name="test-associate-resolver-rule",
            VPCId=vpc_id,
        )["ResolverRuleAssociation"]

        assert self._wait_associate_or_disassociate_resolver_rule(
            aws_client.route53resolver, resolver_rule_id, vpc_id, "associate"
        )
        rule_association = aws_client.route53resolver.get_resolver_rule_association(
            ResolverRuleAssociationId=associated_resolver_rule_res["Id"]
        )
        snapshot.match("rule_association", rule_association)

        disassociate_resolver_rule_res = aws_client.route53resolver.disassociate_resolver_rule(
            ResolverRuleId=resolver_rule_id, VPCId=vpc_id
        )
        # wait till resolver rule is disassociated
        self._wait_associate_or_disassociate_resolver_rule(
            aws_client.route53resolver, resolver_rule_id, vpc_id, "disassociate"
        )
        snapshot.match("disassociate_resolver_rule_res", disassociate_resolver_rule_res)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..ManagedOwnerName"])
    def test_list_firewall_domain_lists(self, cleanups, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.key_value("Id"))

        tags = [{"Key": "hello", "Value": "world"}]
        firewall_name = "my_firewall_domain"

        result = aws_client.route53resolver.create_firewall_domain_list(
            CreatorRequestId="test", Name=firewall_name, Tags=tags
        )
        snapshot.match("create-firewall-domain-list", result)
        arn = result["FirewallDomainList"]["Arn"]
        firewall_id = result["FirewallDomainList"]["Id"]
        cleanups.append(
            lambda: aws_client.route53resolver.delete_firewall_domain_list(
                FirewallDomainListId=firewall_id
            )
        )

        result_list = aws_client.route53resolver.list_firewall_domain_lists()
        extracted = [r for r in result_list["FirewallDomainLists"] if r["Name"] == firewall_name]
        snapshot.match("list-firewall-domain-list-filtered", extracted)

        tag_result = aws_client.route53resolver.list_tags_for_resource(ResourceArn=arn)
        snapshot.match("list-tags-for-resource", tag_result)
