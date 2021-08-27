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
            alias_target = attrs.get("AliasTarget", {})
            alias_target["EvaluateTargetHealth"] = alias_target.get("EvaluateTargetHealth", False)
            return {
                "Comment": params.get("Comment", ""),
                "Changes": [{"Action": "CREATE", "ResourceRecordSet": attrs}],
            }

        return {
            "create": {
                "function": "change_resource_record_sets",
                "parameters": {
                    "HostedZoneId": "HostedZoneId",
                    "ChangeBatch": param_change_batch,
                },
            }
        }
