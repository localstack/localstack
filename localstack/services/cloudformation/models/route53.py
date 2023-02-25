from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import select_attributes


class Route53RecordSet(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Route53::RecordSet"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name")  # Ref attribute is the domain name itself

    def fetch_state(self, stack_name, resources):
        route53 = aws_stack.connect_to_service("route53")
        props = self.props
        result = route53.list_resource_record_sets(HostedZoneId=props["HostedZoneId"])[
            "ResourceRecordSets"
        ]
        result = [r for r in result if r["Name"] == props["Name"] and r["Type"] == props["Type"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def param_change_batch(params, **kwargs):
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
            attrs = select_attributes(params, attr_names)

            if isinstance(attrs["TTL"], str):
                attrs["TTL"] = int(attrs["TTL"])

            alias_target = attrs.get("AliasTarget", {})
            alias_target["EvaluateTargetHealth"] = alias_target.get("EvaluateTargetHealth", False)
            if "ResourceRecords" in attrs:
                attrs["ResourceRecords"] = [{"Value": r} for r in attrs["ResourceRecords"]]
            return {
                "Comment": params.get("Comment", ""),
                "Changes": [{"Action": "CREATE", "ResourceRecordSet": attrs}],
            }

        def hosted_zone_id_change_batch(params, **kwargs):
            route53 = aws_stack.connect_to_service("route53")
            hosted_zone_id = params.get("HostedZoneId")
            if not hosted_zone_id:
                hosted_zone_name = params.get("HostedZoneName")
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

        return {
            "create": {
                "function": "change_resource_record_sets",
                "parameters": {
                    "HostedZoneId": hosted_zone_id_change_batch,
                    "ChangeBatch": param_change_batch,
                },
            }
        }
