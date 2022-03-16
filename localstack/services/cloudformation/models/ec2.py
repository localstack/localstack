from moto.ec2.utils import generate_route_id

from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import REF_ID_ATTRS, GenericBaseModel
from localstack.utils.aws import aws_stack


class EC2RouteTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::RouteTable"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        tags_filters = map(
            lambda tag: {"Name": f"tag:{tag.get('Key')}", "Values": [tag.get("Value")]},
            self.props.get("Tags") or [],
        )
        filters = [
            {"Name": "vpc-id", "Values": [self.props["VpcId"]]},
            {"Name": "association.main", "Values": ["false"]},
        ]
        filters.extend(tags_filters)
        route_tables = client.describe_route_tables(Filters=filters)["RouteTables"]
        return (route_tables or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("RouteTableId")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_route_table",
                "parameters": {
                    "VpcId": "VpcId",
                    "TagSpecifications": lambda params, **kwargs: [
                        {"ResourceType": "route-table", "Tags": params.get("Tags")}
                    ],
                },
            },
            "delete": {
                "function": "delete_route_table",
                "parameters": {"RouteTableId": "RouteTableId"},
            },
        }


class EC2Route(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::Route"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        props = self.props
        dst_cidr = self.resolve_refs_recursively(
            stack_name, props.get("DestinationCidrBlock"), resources
        )
        dst_cidr6 = self.resolve_refs_recursively(
            stack_name, props.get("DestinationIpv6CidrBlock"), resources
        )
        table_id = self.resolve_refs_recursively(stack_name, props.get("RouteTableId"), resources)
        route_tables = client.describe_route_tables()["RouteTables"]
        route_table = ([t for t in route_tables if t["RouteTableId"] == table_id] or [None])[0]
        if route_table:
            routes = route_table.get("Routes", [])
            route = [
                r
                for r in routes
                if r.get("DestinationCidrBlock") == (dst_cidr or "_not_set_")
                or r.get("DestinationIpv6CidrBlock") == (dst_cidr6 or "_not_set_")
            ]
            return (route or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        return generate_route_id(
            props.get("RouteTableId"),
            props.get("DestinationCidrBlock"),
            props.get("DestinationIpv6CidrBlock"),
        )

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_route",
                "parameters": {
                    "DestinationCidrBlock": "DestinationCidrBlock",
                    "DestinationIpv6CidrBlock": "DestinationIpv6CidrBlock",
                    "RouteTableId": "RouteTableId",
                },
            },
            "delete": {
                "function": "delete_route",
                "parameters": {
                    "DestinationCidrBlock": "DestinationCidrBlock",
                    "DestinationIpv6CidrBlock": "DestinationIpv6CidrBlock",
                    "RouteTableId": "RouteTableId",
                },
            },
        }


class EC2InternetGateway(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::InternetGateway"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        gateways = client.describe_internet_gateways()["InternetGateways"]
        tags = self.props.get("Tags")
        gateway = [g for g in gateways if (g.get("Tags") or []) == (tags or [])]
        return (gateway or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("InternetGatewayId")

    @staticmethod
    def get_deploy_templates():
        def _create_params(params, **kwargs):
            return {
                "TagSpecifications": [
                    {"ResourceType": "internet-gateway", "Tags": params.get("Tags", [])}
                ]
            }

        return {
            "create": {
                "function": "create_internet_gateway",
                "parameters": _create_params,
            }
        }


class EC2SubnetRouteTableAssociation(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::SubnetRouteTableAssociation"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        props = self.props
        table_id = self.resolve_refs_recursively(stack_name, props.get("RouteTableId"), resources)
        gw_id = self.resolve_refs_recursively(stack_name, props.get("GatewayId"), resources)
        route_tables = client.describe_route_tables()["RouteTables"]
        route_table = ([t for t in route_tables if t["RouteTableId"] == table_id] or [None])[0]
        subnet_id = self.resolve_refs_recursively(stack_name, props.get("SubnetId"), resources)
        if route_table:
            associations = route_table.get("Associations", [])
            association = [a for a in associations if a.get("GatewayId") == gw_id]
            if subnet_id:
                association = [a for a in associations if a.get("SubnetId") == subnet_id]
            return (association or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("RouteTableAssociationId")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "associate_route_table",
                "parameters": {
                    "GatewayId": "GatewayId",
                    "RouteTableId": "RouteTableId",
                    "SubnetId": "SubnetId",
                },
            },
            "delete": {
                "function": "disassociate_route_table",
                "parameters": {"AssociationId": "RouteTableAssociationId"},
            },
        }


class EC2VPCGatewayAttachment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::VPCGatewayAttachment"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        props = self.props
        igw_id = self.resolve_refs_recursively(
            stack_name, props.get("InternetGatewayId"), resources
        )
        vpngw_id = self.resolve_refs_recursively(stack_name, props.get("VpnGatewayId"), resources)
        gateways = []
        if igw_id:
            gateways = client.describe_internet_gateways()["InternetGateways"]
            gateways = [g for g in gateways if g["InternetGatewayId"] == igw_id]
        elif vpngw_id:
            gateways = client.describe_vpn_gateways()["VpnGateways"]
            gateways = [g for g in gateways if g["VpnGatewayId"] == vpngw_id]
        gateway = (gateways or [{}])[0]
        attachments = gateway.get("Attachments") or gateway.get("VpcAttachments") or []
        result = [a for a in attachments if a.get("State") in ("attached", "available")]
        if result:
            return gateway

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        gw_id = props.get("VpnGatewayId") or props.get("InternetGatewayId")
        attachment = (props.get("Attachments") or props.get("VpcAttachments") or [{}])[0]
        if attachment:
            result = "%s-%s" % (gw_id, attachment.get("VpcId"))
            return result

    @classmethod
    def get_deploy_templates(cls):
        def _attach_gateway(resource_id, resources, *args, **kwargs):
            client = aws_stack.connect_to_service("ec2")
            resource = cls(resources[resource_id])
            props = resource.props
            igw_id = props.get("InternetGatewayId")
            vpngw_id = props.get("VpnGatewayId")
            vpc_id = props.get("VpcId")
            if igw_id:
                client.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw_id)
            elif vpngw_id:
                client.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vpngw_id)

        return {"create": {"function": _attach_gateway}}


class SecurityGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::SecurityGroup"

    def fetch_state(self, stack_name, resources):
        props = self.props
        group_id = props.get("GroupId")
        group_name = props.get("GroupName")
        client = aws_stack.connect_to_service("ec2")
        if group_id:
            resp = client.describe_security_groups(GroupIds=[group_id])
        else:
            resp = client.describe_security_groups(GroupNames=[group_name])
        return (resp["SecurityGroups"] or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if self.physical_resource_id:
            return self.physical_resource_id
        if attribute in REF_ID_ATTRS:
            props = self.props
            return props.get("GroupId") or props.get("GroupName")

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("GroupName")
        if not role_name:
            resource["Properties"]["GroupName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_security_group",
                "parameters": {
                    "GroupName": "GroupName",
                    "VpcId": "VpcId",
                    "Description": "GroupDescription",
                },
            },
            "delete": {
                "function": "delete_security_group",
                "parameters": {"GroupId": "PhysicalResourceId"},
            },
        }


class EC2Subnet(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::Subnet"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        props = self.props
        filters = [
            {"Name": "cidr-block", "Values": [props["CidrBlock"]]},
            {"Name": "vpc-id", "Values": [props["VpcId"]]},
        ]
        subnets = client.describe_subnets(Filters=filters)["Subnets"]
        return (subnets or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("SubnetId")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_subnet",
                "parameters": {
                    "VpcId": "VpcId",
                    "CidrBlock": "CidrBlock",
                    "OutpostArn": "OutpostArn",
                    "Ipv6CidrBlock": "Ipv6CidrBlock",
                    "AvailabilityZone": "AvailabilityZone"
                    # TODO: add TagSpecifications
                },
            },
            "delete": {
                "function": "delete_subnet",
                "parameters": {"SubnetId": "PhysicalResourceId"},
            },
        }


class EC2VPC(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::VPC"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        resp = client.describe_vpcs(Filters=[{"Name": "cidr", "Values": [self.props["CidrBlock"]]}])
        return (resp["Vpcs"] or [None])[0]

    def get_cfn_attribute(self, attribute_name):
        ec2_client = aws_stack.connect_to_service("ec2")
        vpc_id = self.state["VpcId"]

        if attribute_name == "DefaultSecurityGroup":
            sgs = ec2_client.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": ["default"]},
                    {"Name": "vpc-id", "Values": [vpc_id]},
                ]
            )["SecurityGroups"]
            if len(sgs) != 1:
                raise Exception(f"There should only be one default group for this VPC ({vpc_id=})")
            return sgs[0]["GroupId"]
        elif attribute_name == "DefaultNetworkAcl":
            acls = ec2_client.describe_network_acls(
                Filters=[
                    {"Name": "default", "Values": ["true"]},
                    {"Name": "vpc-id", "Values": [vpc_id]},
                ]
            )["NetworkAcls"]
            if len(acls) != 1:
                raise Exception(
                    f"There should only be one default network ACL for this VPC ({vpc_id=})"
                )
            return acls[0]["NetworkAclId"]
        else:
            return super(EC2VPC, self).get_cfn_attribute(attribute_name)

    @classmethod
    def get_deploy_templates(cls):
        def _pre_delete(resource_id, resources, resource_type, func, stack_name):
            res = cls(resources[resource_id])
            vpc_id = res.state.get("VpcId")
            if vpc_id:
                ec2_client = aws_stack.connect_to_service("ec2")
                resp = ec2_client.describe_route_tables(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "association.main", "Values": ["false"]},
                    ]
                )
                for rt in resp["RouteTables"]:
                    for assoc in rt.get("Associations", []):
                        # skipping Main association (upstream moto includes default association that cannot be deleted)
                        if assoc.get("Main"):
                            continue
                        ec2_client.disassociate_route_table(
                            AssociationId=assoc["RouteTableAssociationId"]
                        )
                    ec2_client.delete_route_table(RouteTableId=rt["RouteTableId"])

        return {
            "create": {
                "function": "create_vpc",
                "parameters": {
                    "CidrBlock": "CidrBlock",
                    "InstanceTenancy": "InstanceTenancy"
                    # TODO: add TagSpecifications
                },
            },
            "delete": [
                {"function": _pre_delete},
                {
                    "function": "delete_vpc",
                    "parameters": {"VpcId": "PhysicalResourceId"},
                },
            ],
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("VpcId")


class EC2NatGateway(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::NatGateway"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        props = self.props
        subnet_id = self.resolve_refs_recursively(stack_name, props.get("SubnetId"), resources)
        assoc_id = self.resolve_refs_recursively(stack_name, props.get("AllocationId"), resources)
        result = client.describe_nat_gateways(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )
        result = result["NatGateways"]
        result = [
            gw
            for gw in result
            if assoc_id in [ga["AllocationId"] for ga in gw["NatGatewayAddresses"]]
        ]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_nat_gateway",
                "parameters": {
                    "SubnetId": "SubnetId",
                    "AllocationId": "AllocationId"
                    # TODO: add TagSpecifications
                },
            },
            "delete": {
                "function": "delete_nat_gateway",
                "parameters": {"NatGatewayId": "PhysicalResourceId"},
            },
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("NatGatewayId")


class EC2Instance(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::Instance"

    def fetch_state(self, stack_name, resources):
        instance_id = self.get_physical_resource_id()
        if not instance_id:
            return
        return self._get_state()

    def update_resource(self, new_resource, stack_name, resources):
        instance_id = self.get_physical_resource_id()
        props = new_resource["Properties"]
        groups = props.get("SecurityGroups", props.get("SecurityGroupIds"))

        client = aws_stack.connect_to_service("ec2")
        kwargs = {}
        if groups:
            kwargs["Groups"] = groups
        client.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceType={"Value": props["InstanceType"]},
            **kwargs,
        )
        return self._get_state(client)

    def _get_state(self, client=None):
        instance_id = self.get_physical_resource_id()
        client = client or aws_stack.connect_to_service("ec2")
        resp = client.describe_instances(InstanceIds=[instance_id])
        reservation = (resp.get("Reservations") or [{}])[0]
        result = (reservation.get("Instances") or [None])[0]
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("InstanceId")

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in REF_ID_ATTRS:
            return self.props.get("InstanceId")
        if attribute_name == "PublicIp":
            return self.props.get("PublicIpAddress") or "127.0.0.1"
        if attribute_name == "PublicDnsName":
            return self.props.get("PublicDnsName")
        if attribute_name == "AvailabilityZone":
            return (
                self.props.get("Placement", {}).get("AvailabilityZone")
                or f"{aws_stack.get_region()}a"
            )
        return super(EC2Instance, self).get_cfn_attribute(attribute_name)

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_instances",
                "parameters": {
                    "InstanceType": "InstanceType",
                    "SecurityGroups": "SecurityGroups",
                    "KeyName": "KeyName",
                    "ImageId": "ImageId",
                },
                "defaults": {"MinCount": 1, "MaxCount": 1},
            },
            "delete": {
                "function": "terminate_instances",
                "parameters": {
                    "InstanceIds": lambda params, **kw: [
                        kw["resources"][kw["resource_id"]]["PhysicalResourceId"]
                    ]
                },
            },
        }
