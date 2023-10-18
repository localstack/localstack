import json

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils import common
from localstack.utils.common import short_uid


class EventConnection(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::Connection"

    def fetch_state(self, stack_name, resources):
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).events
        conn_name = self.props.get("Name")
        return client.describe_connection(Name=conn_name)

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["ConnectionArn"]
            # TODO
            # resource["Properties"]["SecretArn"] = ?
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]

        return {
            "create": {"function": "create_connection", "result_handler": _handle_result},
            "delete": {"function": "delete_connection", "parameters": ["Name"]},
        }


class EventBus(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::EventBus"

    def fetch_state(self, stack_name, resources):
        event_bus_name = self.props.get("Name")
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).events
        return client.describe_event_bus(Name=event_bus_name)

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["EventBusArn"]
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]

        return {
            "create": {
                "function": "create_event_bus",
                "parameters": ["Name"],
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_event_bus", "parameters": ["Name"]},
        }


class EventsRule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::Rule"

    def fetch_state(self, stack_name, resources):
        rule_name = self.props.get("Name")

        kwargs = {"Name": rule_name}
        if bus_name := self.props.get("EventBusName"):
            kwargs["EventBusName"] = bus_name

        result = (
            connect_to(
                aws_access_key_id=self.account_id, region_name=self.region_name
            ).events.describe_rule(**kwargs)
            or {}
        )
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
        def events_put_rule_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            attrs = [
                "ScheduleExpression",
                "EventPattern",
                "State",
                "Description",
                "Name",
                "EventBusName",
            ]
            result = select_parameters(*attrs)(
                account_id, region_name, properties, logical_resource_id, resource, stack_name
            )

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

        def _delete_rule(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
            props = resource["Properties"]
            rule_name = props["Name"]
            targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
            target_ids = [tgt["Id"] for tgt in targets]
            if targets:
                events.remove_targets(Rule=rule_name, Ids=target_ids, Force=True)
            events.delete_rule(Name=rule_name)

        def _put_targets(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
            props = resource["Properties"]
            rule_name = props["Name"]
            event_bus_name = props.get("EventBusName")
            targets = props.get("Targets") or []
            if len(targets) > 0 and event_bus_name:
                events.put_targets(Rule=rule_name, EventBusName=event_bus_name, Targets=targets)
            elif len(targets) > 0:
                events.put_targets(Rule=rule_name, Targets=targets)

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["RuleArn"]
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]

        return {
            "create": [
                {
                    "function": "put_rule",
                    "parameters": events_put_rule_params,
                    "result_handler": _handle_result,
                },
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
        def _create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
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

        def _delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
            props = resource["Properties"]
            statement_id = props["StatementId"]
            event_bus_name = props.get("EventBusName")
            optional_event_bus_name = {"EventBusName": event_bus_name} if event_bus_name else {}
            try:
                events.remove_permission(
                    StatementId=statement_id, RemoveAllPermissions=False, **optional_event_bus_name
                )
            except Exception as err:
                if (
                    isinstance(err, ClientError)
                    and err.response["Error"]["Code"] == "ResourceNotFoundException"
                ):
                    pass  # expected behavior ("parent" resource event bus already deleted)
                else:
                    raise err

        return {
            "create": {"function": _create},
            "delete": {"function": _delete},
        }


# TODO: AWS::Events::Archive
