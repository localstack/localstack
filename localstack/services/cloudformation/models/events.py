import json

from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    select_parameters,
)
from localstack.services.cloudformation.service_models import (
    REF_ATTRS,
    REF_ID_ATTRS,
    GenericBaseModel,
)
from localstack.utils import common
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import short_uid


class EventConnection(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::Connection"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("events")
        conn_name = self.resolve_refs_recursively(stack_name, self.props.get("Name"), resources)
        return client.describe_connection(Name=conn_name)

    def get_cfn_attribute(self, attribute_name):
        props = self.props
        if attribute_name in REF_ID_ATTRS:
            return props.get("Name")
        if attribute_name == "Arn":
            return props.get("ConnectionArn")
        # TODO: handle "SecretArn" attribute
        return super(EventConnection, self).get_cfn_attribute(attribute_name)

    @classmethod
    def get_deploy_templates(cls):
        return {
            "create": {"function": "create_connection"},
            "delete": {"function": "delete_connection", "parameters": ["Name"]},
        }


class EventBus(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::EventBus"

    def fetch_state(self, stack_name, resources):
        event_bus_name = self.resolve_refs_recursively(
            stack_name, self.props.get("Name"), resources
        )
        client = aws_stack.connect_to_service("events")
        return client.describe_event_bus(Name=event_bus_name)

    def get_cfn_attribute(self, attribute_name):
        props = self.props
        if attribute_name in REF_ATTRS + ["Name"]:
            return props.get("Name")
        if attribute_name == "Arn":
            return props.get("Arn")
        return super(EventBus, self).get_cfn_attribute(attribute_name)

    @classmethod
    def get_deploy_templates(cls):
        return {
            "create": {"function": "create_event_bus", "parameters": ["Name"]},
            "delete": {"function": "delete_event_bus", "parameters": ["Name"]},
        }


class EventsRule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::Rule"

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "Arn":
            return self.params.get("Arn") or arns.events_rule_arn(self.params.get("Name"))
        return super(EventsRule, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name")

    def fetch_state(self, stack_name, resources):
        rule_name = self.resolve_refs_recursively(stack_name, self.props.get("Name"), resources)
        result = aws_stack.connect_to_service("events").describe_rule(Name=rule_name) or {}
        return result if result.get("Name") else None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("Name")
        if not role_name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def events_put_rule_params(params, **kwargs):
            attrs = [
                "ScheduleExpression",
                "EventPattern",
                "State",
                "Description",
                "Name",
                "EventBusName",
            ]
            result = select_parameters(*attrs)(params, **kwargs)

            # TODO: remove this when refactoring events (prefix etc. was excluded here already to avoid most of the wrong behavior)
            def wrap_in_lists(o, **kwargs):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if not isinstance(v, (dict, list)) and k not in [
                            "prefix",
                            "cidr",
                            "exists",
                        ]:
                            o[k] = [v]
                return o

            pattern = result.get("EventPattern")
            if isinstance(pattern, dict):
                wrapped = common.recurse_object(pattern, wrap_in_lists)
                result["EventPattern"] = json.dumps(wrapped)
            return result

        def _delete_rule(resource_id, resources, *args, **kwargs):
            events = aws_stack.connect_to_service("events")
            resource = resources[resource_id]
            props = resource["Properties"]
            rule_name = props["Name"]
            targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
            target_ids = [tgt["Id"] for tgt in targets]
            if targets:
                events.remove_targets(Rule=rule_name, Ids=target_ids, Force=True)
            events.delete_rule(Name=rule_name)

        def _put_targets(resource_id, resources, *args, **kwargs):
            events = aws_stack.connect_to_service("events")
            resource = resources[resource_id]
            props = resource["Properties"]
            rule_name = props["Name"]
            event_bus_name = props.get("EventBusName")
            targets = props.get("Targets") or []
            if len(targets) > 0 and event_bus_name:
                events.put_targets(Rule=rule_name, EventBusName=event_bus_name, Targets=targets)
            elif len(targets) > 0:
                events.put_targets(Rule=rule_name, Targets=targets)

        return {
            "create": [
                {"function": "put_rule", "parameters": events_put_rule_params},
                {"function": _put_targets},
            ],
            "delete": {"function": _delete_rule},
        }


class EventBusPolicy(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::Events::EventBusPolicy"

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name):
            events = aws_stack.connect_to_service("events")
            resource = resources[resource_id]
            props = resource["Properties"]

            resource["PhysicalResourceId"] = f"EventBusPolicy-{short_uid()}"

            statement_id = props["StatementId"]  # required
            event_bus_name = props.get("EventBusName")  # optional
            statement = props.get(
                "Statement"
            )  # either this field  is set or all other fields (Action, Principal, etc.)

            optional_event_bus_name = {"EventBusName": event_bus_name} if event_bus_name else {}

            if statement is not None:
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": statement_id,
                            **statement,
                        }
                    ],
                }
                events.put_permission(Policy=json.dumps(policy), **optional_event_bus_name)
            else:
                condition = props.get("Condition")
                optional_condition = {"Condition": condition} if condition else {}
                events.put_permission(
                    StatementId=statement_id,
                    Action=props["Action"],
                    Principal=props["Principal"],
                    **optional_event_bus_name,
                    **optional_condition,
                )

        def _delete(resource_id, resources, resource_type, func, stack_name):
            events = aws_stack.connect_to_service("events")
            resource = resources[resource_id]
            props = resource["Properties"]
            statement_id = props["StatementId"]
            event_bus_name = props.get("EventBusName")
            optional_event_bus_name = {"EventBusName": event_bus_name} if event_bus_name else {}
            try:
                events.remove_permission(
                    StatementId=statement_id, RemoveAllPermissions=False, **optional_event_bus_name
                )
            except Exception as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    pass  # expected behavior ("parent" resource event bus already deleted)
                else:
                    raise err

        return {
            "create": {"function": _create},
            "delete": {"function": _delete},
        }


# TODO: AWS::Events::Archive
