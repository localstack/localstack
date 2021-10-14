import json

from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_RESOURCE_NAME,
    pre_create_default_name,
    select_parameters,
)
from localstack.services.cloudformation.service_models import (
    REF_ATTRS,
    REF_ID_ATTRS,
    GenericBaseModel,
)
from localstack.utils import common
from localstack.utils.aws import aws_stack
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
            "delete": {"function": "delete_connection", "parameters": {"Name": "Name"}},
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
            "create": {"function": "create_event_bus", "parameters": {"Name": "Name"}},
            "delete": {"function": "delete_event_bus", "parameters": {"Name": "Name"}},
        }


class EventsRule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::Rule"

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "Arn":
            return self.params.get("Arn") or aws_stack.events_rule_arn(self.params.get("Name"))
        return super(EventsRule, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name")

    def fetch_state(self, stack_name, resources):
        rule_name = self.resolve_refs_recursively(stack_name, self.props.get("Name"), resources)
        result = aws_stack.connect_to_service("events").describe_rule(Name=rule_name) or {}
        return result if result.get("Name") else None

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

            def wrap_in_lists(o, **kwargs):
                if isinstance(o, dict):
                    for k, v in o.items():
                        if not isinstance(v, (dict, list)):
                            o[k] = [v]
                return o

            pattern = result.get("EventPattern")
            if isinstance(pattern, dict):
                wrapped = common.recurse_object(pattern, wrap_in_lists)
                result["EventPattern"] = json.dumps(wrapped)
            return result

        return {
            "create": [
                {"function": pre_create_default_name("Name")},
                {"function": "put_rule", "parameters": events_put_rule_params},
                {
                    "function": "put_targets",
                    "parameters": {
                        "Rule": PLACEHOLDER_RESOURCE_NAME,
                        "EventBusName": "EventBusName",
                        "Targets": "Targets",
                    },
                },
            ],
            "delete": {
                "function": "delete_rule",
                "parameters": {"Name": "PhysicalResourceId"},
            },
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

            event_bus_name = props.get("EventBusName")
            policy = props.get("Statement")  # either this field  is set or all other fields
            statement_id = props.get("StatementId")
            if policy is not None:
                events.put_permission(EventBusName=event_bus_name, Policy=json.dumps(policy))
            else:
                condition = props.get("Condition")
                if condition is not None:
                    events.put_permission(
                        EventBusName=event_bus_name,
                        StatementId=statement_id,
                        Action=props["Action"],
                        Principal=props["Principal"],
                        Condition=condition,
                    )
                else:
                    # note: setting condition to None here is *NOT* equivalent to not specifying it and will throw
                    events.put_permission(
                        EventBusName=event_bus_name,
                        StatementId=statement_id,
                        Action=props["Action"],
                        Principal=props["Principal"],
                    )

        def _delete(resource_id, resources, resource_type, func, stack_name):
            events = aws_stack.connect_to_service("events")
            resource = resources[resource_id]
            props = resource["Properties"]
            event_bus_name = props.get("EventBusName")
            statement_id = props.get("StatementId")
            try:
                events.remove_permission(
                    EventBusName=event_bus_name,
                    StatementId=statement_id,
                    RemoveAllPermissions=False,
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
