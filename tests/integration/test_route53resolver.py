import logging
import random
import re

import pytest

from localstack.aws.api.route53resolver import (
    ListResolverEndpointsResponse,
    ListResolverQueryLogConfigsResponse,
    ListResolverRuleAssociationsResponse,
)
from localstack.testing.pytest.marking import Markers
from localstack.utils.common import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def route53resolver_api_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.route53resolver_api())


class TestRoute53Resolver:
    @staticmethod
    def get_create_resolver_endpoint_ip_address(client, hostId):
        # getting list of existing (default) subnets
        subnets = client.describe_subnets()["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets]
        # construct IPs within CIDR range
        ips = [re.sub(r"(.*)\.[0-9]+/.+", r"\1." + hostId, s["CidrBlock"]) for s in subnets]
        return [
            {"SubnetId": subnet_ids[0], "Ip": ips[0]},
            {"SubnetId": subnet_ids[1], "Ip": ips[1]},
        ]

    @staticmethod
    def get_security_group_ids(client):
        security_groups_ids = []
        security_groups_response = client.describe_security_groups()["SecurityGroups"]
        security_groups_ids = [sg["GroupId"] for sg in security_groups_response]
        return security_groups_ids

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
                f"Timed out while awaiting for resolver rule to {action} with with VPCId:'{vpc_id}' and ResolverRuleId: '{resolver_rule_id}'."
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
                f"Timed out while awaiting for resolver query log config with with id:'{id}' to become listable."
            )
        else:
            return True

    @staticmethod
    def _wait_created_endpoint_is_listed_with_status(client, req_id, status):
        def _is_req_id_in_list():
            lst: ListResolverEndpointsResponse = client.list_resolver_endpoints()
            resolver_endpoint_request_ids_status = {}

            for resolver_endpoint in lst.get("ResolverEndpoints", []):
                resolver_endpoint_request_ids_status[
                    resolver_endpoint["CreatorRequestId"]
                ] = resolver_endpoint["Status"]
            for key, value in resolver_endpoint_request_ids_status.items():
                if key == req_id:
                    return value == status
            return False

        if not poll_condition(condition=_is_req_id_in_list, timeout=180, interval=2):
            LOG.warning(
                f"Timed out while awaiting for resolver endpoint with with request id:'{req_id}' to become listable."
            )
        else:
            return True

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    @pytest.mark.parametrize(
        "direction, hostId",
        [
            ("INBOUND", "5"),
            ("OUTBOUND", "10"),
        ],
    )
    def test_create_resolver_endpoint(self, direction, hostId, cleanups, snapshot, aws_client):

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction=direction,
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, hostId),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        # clean up
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

    @Markers.parity.aws_validated
    def test_route53resolver_bad_create_endpoint_security_groups(self, snapshot, aws_client):
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
                IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "43"),
            )
        snapshot.match("inavlid_param_request_res", inavlid_param_request_res.value.response)

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_multiple_create_resolver_endpoint_with_same_req_id(
        self, cleanups, snapshot, aws_client
    ):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        ip_addresses = self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "41")
        security_groups_ids = self.get_security_group_ids(aws_client.ec2)
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=security_groups_ids,
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=ip_addresses,
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
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
                SecurityGroupIds=security_groups_ids,
                Direction="INBOUND",
                Name=resolver_endpoint_name,
                IpAddresses=ip_addresses,
            )

        snapshot.match(
            "res_exists_ex_error_code", res_exists_ex.value.response.get("Error", {}).get("Code")
        )
        snapshot.match(
            "res_exists_ex_http_status_code",
            res_exists_ex.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_update_resolver_endpoint(self, cleanups, snapshot, aws_client):
        request_id = short_uid()
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="INBOUND",
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "58"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
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

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_delete_resolver_endpoint(self, cleanups, snapshot, aws_client):
        request_id = short_uid()
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="INBOUND",
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "48"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        self._wait_created_endpoint_is_listed_with_status(
            aws_client.route53resolver, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        delete_resolver_endpoint = aws_client.route53resolver.delete_resolver_endpoint(
            ResolverEndpointId=create_resolver_endpoint_res["Id"]
        )
        snapshot.match("delete_resolver_endpoint_res", delete_resolver_endpoint)

    @Markers.parity.aws_validated
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

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_create_resolver_rule(self, cleanups, snapshot, aws_client):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "38"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        # clean up
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
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

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_create_resolver_rule_with_invalid_direction(self, cleanups, snapshot, aws_client):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "28"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        # clean up
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
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

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_multipe_create_resolver_rule(self, cleanups, snapshot, aws_client):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "18"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]

        # clean up
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=resolver_endpoint_id
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

    @Markers.parity.aws_validated
    def test_delete_non_existent_resolver_rule(self, snapshot, aws_client):
        resolver_rule_id = "id-123"
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.delete_resolver_rule(ResolverRuleId=resolver_rule_id)
        snapshot.match("resource_not_found_res", resource_not_found.value.response)

    @Markers.parity.aws_validated
    def test_disassociate_non_existent_association(self, snapshot, aws_client):
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.disassociate_resolver_rule(
                ResolverRuleId="rslvr-123", VPCId="vpc-123"
            )
        snapshot.match("resource_not_found_res", resource_not_found)

    @Markers.parity.aws_validated
    def test_create_resolver_query_log_config(self, cleanups, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.key_value("Name"))
        request_id = short_uid()
        result = aws_client.route53resolver.create_resolver_query_log_config(
            Name=f"test-{short_uid()}",
            DestinationArn="arn:aws:logs:us-east-1:123456789012:log-group:sampletest123",
            CreatorRequestId=request_id,
        )
        create_rqlc = result.get("ResolverQueryLogConfig")
        resolver_config_id = create_rqlc["Id"]
        if self._wait_created_log_config_is_listed_with_status(
            aws_client.route53resolver, resolver_config_id, "CREATED"
        ):
            create_rqlc["Status"] = "CREATED"

        snapshot.match("create_resolver_query_log_config_res", create_rqlc)

        delete_resolver_config = aws_client.route53resolver.delete_resolver_query_log_config(
            ResolverQueryLogConfigId=resolver_config_id
        )
        snapshot.match("delete_resolver_query_log_config_res", delete_resolver_config)

    @Markers.parity.aws_validated
    def test_delete_non_existent_resolver_query_log_config(self, snapshot, aws_client):
        resolver_rqlc_id = "test_123"
        with pytest.raises(
            aws_client.route53resolver.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            aws_client.route53resolver.delete_resolver_query_log_config(
                ResolverQueryLogConfigId=resolver_rqlc_id
            )
        snapshot.match(
            "resource_not_found_ex_error_code",
            resource_not_found.value.response.get("Error", {}).get("Code"),
        )
        snapshot.match(
            "resource_not_found_ex_http_status_code",
            resource_not_found.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(
        paths=["$..SecurityGroupIds", "$..ShareStatus", "$..StatusMessage"]
    )
    def test_associate_and_disassociate_resolver_rule(self, cleanups, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.key_value("ResolverRuleId", "rslvr-rr-id"))
        snapshot.add_transformer(snapshot.transform.key_value("VPCId", "vpc-id"))
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = aws_client.route53resolver.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(aws_client.ec2),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(aws_client.ec2, "68"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]
        cleanups.append(
            lambda: aws_client.route53resolver.delete_resolver_endpoint(
                ResolverEndpointId=resolver_endpoint_id
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

        vpcs = aws_client.ec2.describe_vpcs()["Vpcs"]
        vpcId = random.choice(vpcs)["VpcId"]

        associated_resolver_rule_res = aws_client.route53resolver.associate_resolver_rule(
            ResolverRuleId=resolver_rule_id,
            Name="test-associate-resolver-rule",
            VPCId=random.choice(vpcs)["VpcId"],
        )["ResolverRuleAssociation"]

        if self._wait_associate_or_disassociate_resolver_rule(
            aws_client.route53resolver, resolver_rule_id, vpcId, "associate"
        ):
            associated_resolver_rule_res["Status"] = "COMPLETE"
        snapshot.match("associated_resolver_rule_res", associated_resolver_rule_res)

        disassociate_resolver_rule_res = aws_client.route53resolver.disassociate_resolver_rule(
            ResolverRuleId=resolver_rule_id, VPCId=vpcId
        )
        # wait till resolver rule is disassociated
        self._wait_associate_or_disassociate_resolver_rule(
            aws_client.route53resolver, resolver_rule_id, vpcId, "disassociate"
        )
        snapshot.match("disassociate_resolver_rule_res", disassociate_resolver_rule_res)

    @Markers.parity.aws_validated
    @Markers.snapshot.skip_snapshot_verify(paths=["$..ManagedOwnerName"])
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
