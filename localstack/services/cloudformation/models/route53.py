from localstack.aws.connect import connect_to
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.common import select_attributes
from localstack.utils.strings import short_uid


class Route53RecordSet(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Route53::RecordSet"

    def fetch_state(self, stack_name, resources):
        route53 = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).route53
        props = self.props
        result = route53.list_resource_record_sets(HostedZoneId=props["HostedZoneId"])[
            "ResourceRecordSets"
        ]
        result = [r for r in result if r["Name"] == props["Name"] and r["Type"] == props["Type"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def param_change_batch(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            attr_names = [
                "Name",
                "Type",
                "SetIdentifier",
                "Weight",
                "Region",
                "GeoLocation",
                "Failover",
                "MultiValueAnswer",
                "TTL",
                "ResourceRecords",
                "AliasTarget",
                "HealthCheckId",
            ]
            attrs = select_attributes(properties, attr_names)
            if "TTL" in attrs:
                if isinstance(attrs["TTL"], str):
                    attrs["TTL"] = int(attrs["TTL"])

            alias_target = attrs.get("AliasTarget", {})
            alias_target["EvaluateTargetHealth"] = alias_target.get("EvaluateTargetHealth", False)
            if "ResourceRecords" in attrs:
                attrs["ResourceRecords"] = [{"Value": r} for r in attrs["ResourceRecords"]]
            return {
                "Comment": properties.get("Comment", ""),
                "Changes": [{"Action": "CREATE", "ResourceRecordSet": attrs}],
            }

        def hosted_zone_id_change_batch(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            route53 = connect_to(aws_access_key_id=account_id, region_name=region_name).route53
            hosted_zone_id = properties.get("HostedZoneId")
            if not hosted_zone_id:
                hosted_zone_name = properties.get("HostedZoneName")
                # https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html"
                # "Specify either HostedZoneName or HostedZoneId, but not both. If you have multiple hosted zones with
                # the same domain name, you must specify the hosted zone using HostedZoneId."
                if not hosted_zone_name:
                    raise Exception("Either HostedZoneId or HostedZoneName must be present.")
                hosted_zones = route53.list_hosted_zones_by_name(DNSName=hosted_zone_name)[
                    "HostedZones"
                ]
                if len(hosted_zones) != 1:
                    raise Exception(f"Ambiguous HostedZoneName {hosted_zone_name} provided.")
                hosted_zone = hosted_zones[0]
                hosted_zone_id = hosted_zone.get("Id")
            return hosted_zone_id

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]
            if resource["Properties"].get("AliasTarget"):
                resource["Properties"]["HostedZoneId"] = resource["Properties"]["AliasTarget"][
                    "HostedZoneId"
                ]

        return {
            "create": {
                "function": "change_resource_record_sets",
                "parameters": {
                    "HostedZoneId": hosted_zone_id_change_batch,
                    "ChangeBatch": param_change_batch,
                },
                "result_handler": _handle_result,
            }
        }


class Route53HealthCheck(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Route53::HealthCheck"

    @staticmethod
    def add_defaults(resource, stack_name: str):
        props = resource.get("Properties", {})
        if not props.get("CallerReference"):
            props["CallerReference"] = short_uid()

    def fetch_state(self, stack_name, resources):
        client = connect_to().route53
        result = client.list_health_checks()["HealthChecks"]
        result = [z for z in result if z["Id"] == self.props.get("HealthCheckConfig", {}).get("Id")]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def _get_params(resource_props, logical_resource_id, resource_definition, stack_name):
            resource = Route53HealthCheck(resource_definition)
            props = resource.props
            result = select_attributes(props, ["CallerReference", "HealthCheckConfig"])
            return result

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            resource["Properties"]["Id"] = result["HealthCheck"]["Id"]
            resource["PhysicalResourceId"] = result["HealthCheck"]["Id"]

        return {
            "create": {
                "function": "create_health_check",
                "parameters": _get_params,
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_health_check",
                "parameters": {"Id": "PhysicalResourceId"},
            },
        }
