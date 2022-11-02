import logging
import random
import re

import pytest

from localstack.aws.api.route53resolver import (
    ListResolverEndpointsResponse,
    ListResolverQueryLogConfigsResponse,
    ListResolverRuleAssociationsResponse,
)
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    @pytest.mark.parametrize(
        "direction, hostId",
        [
            ("INBOUND", "5"),
            ("OUTBOUND", "10"),
        ],
    )
    def test_create_resolver_endpoint(
        self, ec2_client, route53resolver_client, direction, hostId, cleanups, snapshot
    ):

        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction=direction,
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, hostId),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        # clean up
        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

    @pytest.mark.aws_validated
    def test_route53resolver_bad_create_endpoint_security_groups(
        self, ec2_client, route53resolver_client, snapshot
    ):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        with pytest.raises(
            route53resolver_client.exceptions.InvalidParameterException
        ) as inavlid_param_request_res:
            route53resolver_client.create_resolver_endpoint(
                CreatorRequestId=request_id,
                SecurityGroupIds=["test-invalid-sg-123"],
                Direction="INBOUND",
                Name=resolver_endpoint_name,
                IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "43"),
            )
        snapshot.match("inavlid_param_request_res", inavlid_param_request_res.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_multiple_create_resolver_endpoint_with_same_req_id(
        self, ec2_client, route53resolver_client, cleanups, snapshot
    ):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        ip_addresses = self.get_create_resolver_endpoint_ip_address(ec2_client, "41")
        security_groups_ids = self.get_security_group_ids(ec2_client)
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=security_groups_ids,
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=ip_addresses,
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        with pytest.raises(
            route53resolver_client.exceptions.ResourceExistsException
        ) as res_exists_ex:
            route53resolver_client.create_resolver_endpoint(
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_update_resolver_endpoint(self, ec2_client, route53resolver_client, cleanups, snapshot):
        request_id = short_uid()
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="INBOUND",
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "58"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        # update resolver endpoint
        update_resolver_endpoint_res = route53resolver_client.update_resolver_endpoint(
            ResolverEndpointId=create_resolver_endpoint_res["Id"], Name="resolver_endpoint_name"
        )

        if self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        ):
            update_resolver_endpoint_res["Status"] = "OPERATIONAL"
        snapshot.match("update_resolver_endpoint_res", update_resolver_endpoint_res)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_delete_resolver_endpoint(self, ec2_client, route53resolver_client, cleanups, snapshot):
        request_id = short_uid()
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="INBOUND",
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "48"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        delete_resolver_endpoint = route53resolver_client.delete_resolver_endpoint(
            ResolverEndpointId=create_resolver_endpoint_res["Id"]
        )
        snapshot.match("delete_resolver_endpoint_res", delete_resolver_endpoint)

    @pytest.mark.aws_validated
    def test_delete_non_existent_resolver_endpoint(self, route53resolver_client, snapshot):
        resolver_endpoint_id = "rslvr-123"
        with pytest.raises(
            route53resolver_client.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            route53resolver_client.delete_resolver_endpoint(ResolverEndpointId=resolver_endpoint_id)
        snapshot.match(
            "resource_not_found_ex_error_code",
            resource_not_found.value.response.get("Error", {}).get("Code"),
        )
        snapshot.match(
            "resource_not_found_ex_http_status_code",
            resource_not_found.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_create_resolver_rule(self, ec2_client, route53resolver_client, cleanups, snapshot):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "38"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")

        # clean up
        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        create_resolver_rule_res = route53resolver_client.create_resolver_rule(
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

        delete_resolver_rule_res = route53resolver_client.delete_resolver_rule(
            ResolverRuleId=create_resolver_rule_res["Id"]
        )
        snapshot.match("delete_resolver_rule_res", delete_resolver_rule_res)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds"])
    def test_create_resolver_rule_with_invalid_direction(
        self, ec2_client, route53resolver_client, cleanups, snapshot
    ):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="INBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "28"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        # clean up
        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=create_resolver_endpoint_res["Id"]
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        with pytest.raises(
            route53resolver_client.exceptions.InvalidRequestException
        ) as inavlid_request:
            route53resolver_client.create_resolver_rule(
                CreatorRequestId=short_uid(),
                RuleType="FORWARD",
                DomainName="www.example2.com",
                ResolverEndpointId=create_resolver_endpoint_res["Id"],
                TargetIps=[
                    {"Ip": "10.0.1.200", "Port": 123},
                ],
            )

        snapshot.match("invalid_request_ex", inavlid_request.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..SecurityGroupIds", "$..ShareStatus"])
    def test_multipe_create_resolver_rule(
        self, ec2_client, route53resolver_client, cleanups, snapshot
    ):
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "18"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]

        # clean up
        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=resolver_endpoint_id
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        rslvr_rule_req_ids = [short_uid(), short_uid(), short_uid()]
        for ind, req_id in enumerate(rslvr_rule_req_ids):
            create_resolver_rule_res = route53resolver_client.create_resolver_rule(
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

            delete_resolver_rule = route53resolver_client.delete_resolver_rule(
                ResolverRuleId=resolver_rule_id
            )
            snapshot.match(f"delete_resolver_rule_res{ind}", delete_resolver_rule)

    @pytest.mark.aws_validated
    def test_delete_non_existent_resolver_rule(self, route53resolver_client, snapshot):
        resolver_rule_id = "id-123"
        with pytest.raises(
            route53resolver_client.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            route53resolver_client.delete_resolver_rule(ResolverRuleId=resolver_rule_id)
        snapshot.match("resource_not_found_res", resource_not_found.value.response)

    @pytest.mark.aws_validated
    def test_disassociate_non_existent_association(self, route53resolver_client, snapshot):
        with pytest.raises(
            route53resolver_client.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            route53resolver_client.disassociate_resolver_rule(
                ResolverRuleId="rslvr-123", VPCId="vpc-123"
            )
        snapshot.match("resource_not_found_res", resource_not_found)

    @pytest.mark.aws_validated
    def test_create_resolver_query_log_config(self, route53resolver_client, cleanups, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("Name"))
        request_id = short_uid()
        result = route53resolver_client.create_resolver_query_log_config(
            Name=f"test-{short_uid()}",
            DestinationArn="arn:aws:logs:us-east-1:123456789012:log-group:sampletest123",
            CreatorRequestId=request_id,
        )
        create_rqlc = result.get("ResolverQueryLogConfig")
        resolver_config_id = create_rqlc["Id"]
        if self._wait_created_log_config_is_listed_with_status(
            route53resolver_client, resolver_config_id, "CREATED"
        ):
            create_rqlc["Status"] = "CREATED"

        snapshot.match("create_resolver_query_log_config_res", create_rqlc)

        delete_resolver_config = route53resolver_client.delete_resolver_query_log_config(
            ResolverQueryLogConfigId=resolver_config_id
        )
        snapshot.match("delete_resolver_query_log_config_res", delete_resolver_config)

    @pytest.mark.aws_validated
    def test_delete_non_existent_resolver_query_log_config(self, route53resolver_client, snapshot):
        resolver_rqlc_id = "test_123"
        with pytest.raises(
            route53resolver_client.exceptions.ResourceNotFoundException
        ) as resource_not_found:
            route53resolver_client.delete_resolver_query_log_config(
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=["$..SecurityGroupIds", "$..ShareStatus", "$..StatusMessage"]
    )
    def test_associate_and_disassociate_resolver_rule(
        self, ec2_client, route53resolver_client, cleanups, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.key_value("ResolverRuleId", "rslvr-rr-id"))
        snapshot.add_transformer(snapshot.transform.key_value("VPCId", "vpc-id"))
        request_id = short_uid()
        resolver_endpoint_name = f"rs-{request_id}"
        result = route53resolver_client.create_resolver_endpoint(
            CreatorRequestId=request_id,
            SecurityGroupIds=self.get_security_group_ids(ec2_client),
            Direction="OUTBOUND",
            Name=resolver_endpoint_name,
            IpAddresses=self.get_create_resolver_endpoint_ip_address(ec2_client, "68"),
        )

        create_resolver_endpoint_res = result.get("ResolverEndpoint")
        resolver_endpoint_id = create_resolver_endpoint_res["Id"]
        cleanups.append(
            lambda: route53resolver_client.delete_resolver_endpoint(
                ResolverEndpointId=resolver_endpoint_id
            )
        )

        self._wait_created_endpoint_is_listed_with_status(
            route53resolver_client, request_id, "OPERATIONAL"
        )
        snapshot.match("create_resolver_endpoint_res", create_resolver_endpoint_res)

        create_resolver_rule_res = route53resolver_client.create_resolver_rule(
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
            lambda: route53resolver_client.delete_resolver_rule(ResolverRuleId=resolver_rule_id)
        )

        snapshot.match("create_resolver_rule_res", create_resolver_rule_res)

        vpcs = ec2_client.describe_vpcs()["Vpcs"]
        vpcId = random.choice(vpcs)["VpcId"]

        associated_resolver_rule_res = route53resolver_client.associate_resolver_rule(
            ResolverRuleId=resolver_rule_id,
            Name="test-associate-resolver-rule",
            VPCId=random.choice(vpcs)["VpcId"],
        )["ResolverRuleAssociation"]

        if self._wait_associate_or_disassociate_resolver_rule(
            route53resolver_client, resolver_rule_id, vpcId, "associate"
        ):
            associated_resolver_rule_res["Status"] = "COMPLETE"
        snapshot.match("associated_resolver_rule_res", associated_resolver_rule_res)

        disassociate_resolver_rule_res = route53resolver_client.disassociate_resolver_rule(
            ResolverRuleId=resolver_rule_id, VPCId=vpcId
        )
        # wait till resolver rule is disassociated
        self._wait_associate_or_disassociate_resolver_rule(
            route53resolver_client, resolver_rule_id, vpcId, "disassociate"
        )
        snapshot.match("disassociate_resolver_rule_res", disassociate_resolver_rule_res)
