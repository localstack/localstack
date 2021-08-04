import json
import logging
import os
import re

from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from moto.core.models import CloudFormationModel
from moto.ec2.utils import generate_route_id
from moto.iam.models import Role as MotoRole
from moto.s3.models import FakeBucket
from moto.sqs.models import Queue as MotoQueue

from localstack.constants import AWS_REGION_US_EAST_1, LOCALHOST
from localstack.services.awslambda.lambda_api import (
    LAMBDA_POLICY_NAME_PATTERN,
    get_handler_file_from_name,
)
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_RESOURCE_NAME,
    get_cfn_response_mod_file,
    lambda_keys_to_lower,
    lambda_select_params,
    merge_parameters,
    params_dict_to_list,
    params_list_to_dict,
    params_select_attributes,
    remove_none_values,
    select_parameters,
)
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    camel_to_snake_case,
    canonical_json,
    cp_r,
    is_base64,
    keys_to_lower,
    md5,
    mkdir,
    new_tmp_dir,
    rm_rf,
    save_file,
    select_attributes,
    short_uid,
)
from localstack.utils.testutil import create_zip_file

LOG = logging.getLogger(__name__)

# dict key used to store the deployment state of a resource
KEY_RESOURCE_STATE = "_state_"

# ref attribute definitions
REF_ATTRS = ["PhysicalResourceId", "Ref"]
REF_ID_ATTRS = REF_ATTRS + ["Id"]
REF_ARN_ATTRS = ["Ref", "Arn"]


class DependencyNotYetSatisfied(Exception):
    """Exception indicating that a resource dependency is not (yet) deployed/available."""

    def __init__(self, resource_ids, message=None):
        message = message or "Unresolved dependencies: %s" % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids


class GenericBaseModel(CloudFormationModel):
    """Abstract base class representing a resource model class in LocalStack.
    This class keeps references to a combination of (1) the CF resource
    properties (as defined in the template), and (2) the current deployment
    state of a resource.

    Concrete subclasses will implement convenience methods to manage resources,
    e.g., fetching the latest deployment state, getting the resource name, etc.
    """

    def __init__(self, resource_json, region_name=None, **params):
        self.region_name = region_name or aws_stack.get_region()
        self.resource_json = resource_json
        self.resource_type = resource_json["Type"]
        # Properties, as defined in the resource template
        self.properties = resource_json["Properties"] = resource_json.get("Properties") or {}
        # State, as determined from the deployed resource; use a special dict key here to keep
        # track of state changes within resource_json (this way we encapsulate all state details
        # in `resource_json` and the changes will survive creation of multiple instances of this class)
        self.state = resource_json[KEY_RESOURCE_STATE] = resource_json.get(KEY_RESOURCE_STATE) or {}

    # ----------------------
    # ABSTRACT BASE METHODS
    # ----------------------

    def get_resource_name(self):
        """Return the name of this resource, based on its properties (to be overwritten by subclasses)"""
        return None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        """Determine the physical resource ID (Ref) of this resource (to be overwritten by subclasses)"""
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def fetch_state(self, stack_name, resources):
        """Fetch the latest deployment state of this resource, or return None if not currently deployed."""
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def update_resource(self, new_resource, stack_name, resources):
        """Update the deployment of this resource, using the updated properties (implemented by subclasses)."""
        # TODO: evaluate if we can add a generic implementation here, using "update" parameters from
        # get_deploy_templates() responses, and based on checking whether resource attributes have changed
        pass

    @classmethod
    def cloudformation_type(cls):
        """Return the CloudFormation resource type name, e.g., "AWS::S3::Bucket" (implemented by subclasses)."""
        return super(GenericBaseModel, cls).cloudformation_type()

    @staticmethod
    def get_deploy_templates():
        """Return template configurations used to create the final API requests (implemented by subclasses)."""
        pass

    # ----------------------
    # GENERIC BASE METHODS
    # ----------------------

    def get_cfn_attribute(self, attribute_name):
        """Retrieve the given CF attribute for this resource (inherited from moto's CloudFormationModel)"""
        if attribute_name in REF_ARN_ATTRS and hasattr(self, "arn"):
            return self.arn
        if attribute_name in REF_ATTRS:
            result = self.get_physical_resource_id(attribute=attribute_name)
            if result:
                return result
        props = self.props
        if attribute_name in props:
            return props.get(attribute_name)

        raise UnformattedGetAttTemplateException()

    # ---------------------
    # GENERIC UTIL METHODS
    # ---------------------

    def fetch_and_update_state(self, *args, **kwargs):
        from localstack.utils.cloudformation import template_deployer

        try:
            state = self.fetch_state(*args, **kwargs)
            self.update_state(state)
            return state
        except Exception as e:
            if not template_deployer.check_not_found_exception(
                e, self.resource_type, self.properties
            ):
                LOG.debug("Unable to fetch state for resource %s: %s" % (self, e))

    def fetch_state_if_missing(self, *args, **kwargs):
        if not self.state:
            self.fetch_and_update_state(*args, **kwargs)
        return self.state

    def set_resource_state(self, state):
        """Set the deployment state of this resource."""
        self.state = state or {}

    def update_state(self, details):
        """Update the deployment state of this resource (existing attributes will be overwritten)."""
        details = details or {}
        self.state.update(details)
        return self.props

    @property
    def physical_resource_id(self):
        """Return the (cached) physical resource ID."""
        return self.resource_json.get("PhysicalResourceId")

    @property
    def logical_resource_id(self):
        """Return the logical resource ID."""
        return self.resource_json.get("LogicalResourceId")

    @property
    def props(self):
        """Return a copy of (1) the resource properties (from the template), combined with
        (2) the current deployment state properties of the resource."""
        result = dict(self.properties)
        result.update(self.state or {})
        return result

    @property
    def resource_id(self):
        """Return the logical resource ID of this resource (i.e., the ref. name within the stack's resources)."""
        return self.resource_json["LogicalResourceId"]

    @classmethod
    def update_from_cloudformation_json(
        cls, original_resource, new_resource_name, cloudformation_json, region_name
    ):
        props = cloudformation_json.get("Properties", {})
        for key, val in props.items():
            snake_key = camel_to_snake_case(key)
            lower_key = key.lower()
            for candidate in [key, lower_key, snake_key]:
                if hasattr(original_resource, candidate) or candidate == snake_key:
                    setattr(original_resource, candidate, val)
                    break
        return original_resource

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, resource_json, region_name):
        return cls(
            resource_name=resource_name,
            resource_json=resource_json,
            region_name=region_name,
        )

    @classmethod
    def resolve_refs_recursively(cls, stack_name, value, resources):
        # TODO: restructure code to avoid circular import here
        from localstack.utils.cloudformation.template_deployer import resolve_refs_recursively

        return resolve_refs_recursively(stack_name, value, resources)


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
            result["Name"] = result.get("Name") or PLACEHOLDER_RESOURCE_NAME

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


class EventBus(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Events::EventBus"

    def fetch_state(self, stack_name, resources):
        event_bus_name = self.props.get("Name")
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


class LogsLogGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::LogGroup"

    def get_cfn_attribute(self, attribute_name):
        props = self.props
        if attribute_name == "Arn":
            return props.get("arn")
        return super(LogsLogGroup, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute == "Arn":
            return self.get_cfn_attribute("Arn")
        return self.props.get("LogGroupName")

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get("LogGroupName")
        group_name = self.resolve_refs_recursively(stack_name, group_name, resources)
        logs = aws_stack.connect_to_service("logs")
        groups = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
        return ([g for g in groups if g["logGroupName"] == group_name] or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
            },
            "delete": {
                "function": "delete_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
            },
        }


class LogsSubscriptionFilter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::SubscriptionFilter"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("LogGroupName")

    def fetch_state(self, stack_name, resources):
        props = self.props
        group_name = self.resolve_refs_recursively(stack_name, props.get("LogGroupName"), resources)
        filter_pattern = self.resolve_refs_recursively(
            stack_name, props.get("FilterPattern"), resources
        )
        logs = aws_stack.connect_to_service("logs")
        groups = logs.describe_subscription_filters(logGroupName=group_name)["subscriptionFilters"]
        groups = [g for g in groups if g.get("filterPattern") == filter_pattern]
        return (groups or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",  # there can only be one filter associated with a log group
                    "filterPattern": "FilterPattern",
                    "destinationArn": "DestinationArn",
                },
            },
            "delete": {
                "function": "delete_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",
                },
            },
        }


class CloudFormationStack(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudFormation::Stack"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("StackId")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("cloudformation")
        child_stack_name = self.props["StackName"]
        child_stack_name = self.resolve_refs_recursively(stack_name, child_stack_name, resources)
        result = client.describe_stacks(StackName=child_stack_name)
        result = (result.get("Stacks") or [None])[0]
        return result

    @classmethod
    def get_deploy_templates(cls):
        def get_nested_stack_params(params, **kwargs):
            nested_stack_name = params["StackName"]
            stack_params = params.get("Parameters", {})
            stack_params = [
                {
                    "ParameterKey": k,
                    "ParameterValue": str(v).lower() if isinstance(v, bool) else str(v),
                }
                for k, v in stack_params.items()
            ]
            result = {
                "StackName": nested_stack_name,
                "TemplateURL": params.get("TemplateURL"),
                "Parameters": stack_params,
            }
            return result

        return {
            "create": {
                "function": "create_stack",
                "parameters": get_nested_stack_params,
            }
        }


class LambdaFunction(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Function"

    def fetch_state(self, stack_name, resources):
        func_name = self.resolve_refs_recursively(stack_name, self.props["FunctionName"], resources)
        return aws_stack.connect_to_service("lambda").get_function(FunctionName=func_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        func_name = self.props.get("FunctionName")
        if attribute == "Arn":
            return aws_stack.lambda_function_arn(func_name)
        return func_name

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("lambda")
        keys = (
            "FunctionName",
            "Role",
            "Handler",
            "Description",
            "Timeout",
            "MemorySize",
            "Environment",
            "Runtime",
        )
        update_props = dict([(k, props[k]) for k in keys if k in props])
        update_props = self.resolve_refs_recursively(stack_name, update_props, resources)
        if "Timeout" in update_props:
            update_props["Timeout"] = int(update_props["Timeout"])
        if "Code" in props:
            code = props["Code"] or {}
            if not code.get("ZipFile"):
                LOG.debug(
                    'Updating code for Lambda "%s" from location: %s'
                    % (props["FunctionName"], code)
                )
            client.update_function_code(FunctionName=props["FunctionName"], **code)
        if "Environment" in update_props:
            environment_variables = update_props["Environment"].get("Variables", {})
            update_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }
        return client.update_function_configuration(**update_props)

    @staticmethod
    def get_deploy_templates():
        def get_lambda_code_param(params, **kwargs):
            code = params.get("Code", {})
            zip_file = code.get("ZipFile")
            if zip_file and not is_base64(zip_file):
                tmp_dir = new_tmp_dir()
                handler_file = get_handler_file_from_name(
                    params["Handler"], runtime=params["Runtime"]
                )
                tmp_file = os.path.join(tmp_dir, handler_file)
                save_file(tmp_file, zip_file)

                # add 'cfn-response' module to archive - see:
                # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
                cfn_response_tmp_file = get_cfn_response_mod_file()
                cfn_response_mod_dir = os.path.join(tmp_dir, "node_modules", "cfn-response")
                mkdir(cfn_response_mod_dir)
                cp_r(
                    cfn_response_tmp_file,
                    os.path.join(cfn_response_mod_dir, "index.js"),
                )

                # create zip file
                zip_file = create_zip_file(tmp_dir, get_content=True)
                code["ZipFile"] = zip_file
                rm_rf(tmp_dir)
            return code

        def get_delete_params(params, **kwargs):
            return {"FunctionName": params.get("FunctionName")}

        return {
            "create": {
                "function": "create_function",
                "parameters": {
                    "FunctionName": "FunctionName",
                    "Runtime": "Runtime",
                    "Role": "Role",
                    "Handler": "Handler",
                    "Code": get_lambda_code_param,
                    "Description": "Description",
                    "Environment": "Environment",
                    "Timeout": "Timeout",
                    "MemorySize": "MemorySize",
                    "Layers": "Layers"
                    # TODO add missing fields
                },
                "defaults": {"Role": "test_role"},
                "types": {"Timeout": int, "MemorySize": int},
            },
            "delete": {"function": "delete_function", "parameters": get_delete_params},
        }


class LambdaFunctionVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Version"

    def fetch_state(self, stack_name, resources):
        name = self.resolve_refs_recursively(stack_name, self.props.get("FunctionName"), resources)
        if not name:
            return None
        func_name = aws_stack.lambda_function_name(name)
        func_version = name.split(":")[7] if len(name.split(":")) > 7 else "$LATEST"
        versions = aws_stack.connect_to_service("lambda").list_versions_by_function(
            FunctionName=func_name
        )
        return ([v for v in versions["Versions"] if v["Version"] == func_version] or [None])[0]


class LambdaEventSourceMapping(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventSourceMapping"

    def fetch_state(self, stack_name, resources):
        props = self.props
        resource_id = props["FunctionName"] or self.resource_id
        source_arn = props.get("EventSourceArn")
        resource_id = self.resolve_refs_recursively(stack_name, resource_id, resources)
        source_arn = self.resolve_refs_recursively(stack_name, source_arn, resources)
        if not resource_id or not source_arn:
            raise Exception("ResourceNotFound")
        mappings = aws_stack.connect_to_service("lambda").list_event_source_mappings(
            FunctionName=resource_id, EventSourceArn=source_arn
        )
        mapping = list(
            filter(
                lambda m: m["EventSourceArn"] == source_arn
                and m["FunctionArn"] == aws_stack.lambda_function_arn(resource_id),
                mappings["EventSourceMappings"],
            )
        )
        if not mapping:
            raise Exception("ResourceNotFound")
        return mapping[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("UUID")


class LambdaPermission(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Permission"

    def fetch_state(self, stack_name, resources):
        props = self.props
        func_name = self.resolve_refs_recursively(stack_name, props.get("FunctionName"), resources)
        func_arn = aws_stack.lambda_function_arn(func_name)
        return self.do_fetch_state(func_name, func_arn)

    def do_fetch_state(self, resource_name, resource_arn):
        iam = aws_stack.connect_to_service("iam")
        props = self.props
        policy_name = LAMBDA_POLICY_NAME_PATTERN % resource_name
        policy_arn = aws_stack.policy_arn(policy_name)
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = policy.get("DefaultVersionId")
        policy = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)["PolicyVersion"]
        statements = policy["Document"]["Statement"]
        statements = statements if isinstance(statements, list) else [statements]
        principal = props.get("Principal")
        existing = [
            s
            for s in statements
            if s["Action"] == props["Action"]
            and s["Resource"] == resource_arn
            and (
                not principal
                or s["Principal"] in [principal, {"Service": principal}, {"Service": [principal]}]
            )
        ]
        return existing[0] if existing else None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        # return statement ID here to indicate that the resource has been deployed
        return self.props.get("Sid")

    @staticmethod
    def get_deploy_templates():
        def lambda_permission_params(params, **kwargs):
            result = select_parameters("FunctionName", "Action", "Principal")(params, **kwargs)
            result["StatementId"] = short_uid()
            return result

        return {
            "create": {
                "function": "add_permission",
                "parameters": lambda_permission_params,
            }
        }


class LambdaEventInvokeConfig(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventInvokeConfig"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("lambda")
        props = self.props
        result = client.get_function_event_invoke_config(
            FunctionName=props.get("FunctionName"),
            Qualifier=props.get("FunctionName", "$LATEST"),
        )
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        return "lambdaconfig-%s-%s" % (
            props.get("FunctionName"),
            props.get("Qualifier"),
        )

    def get_deploy_templates():
        return {
            "create": {"function": "put_function_event_invoke_config"},
            "delete": {
                "function": "delete_function_event_invoke_config",
                "parameters": {
                    "FunctionName": "FunctionName",
                    "Qualifier": "Qualifier",
                },
            },
        }


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Elasticsearch::Domain"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        domain_name = self._domain_name()
        if attribute == "Arn":
            return aws_stack.elasticsearch_domain_arn(domain_name)
        return domain_name

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service("es").describe_elasticsearch_domain(
            DomainName=domain_name
        )

    def _domain_name(self):
        return self.props.get("DomainName") or self.resource_id


class FirehoseDeliveryStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KinesisFirehose::DeliveryStream"

    def fetch_state(self, stack_name, resources):
        stream_name = self.props.get("DeliveryStreamName") or self.resource_id
        stream_name = self.resolve_refs_recursively(stack_name, stream_name, resources)
        return aws_stack.connect_to_service("firehose").describe_delivery_stream(
            DeliveryStreamName=stream_name
        )


class KinesisStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::Stream"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.kinesis_stream_arn(self.props.get("Name"))

    def fetch_state(self, stack_name, resources):
        stream_name = self.resolve_refs_recursively(stack_name, self.props["Name"], resources)
        result = aws_stack.connect_to_service("kinesis").describe_stream(StreamName=stream_name)
        return result

    @staticmethod
    def get_deploy_templates():
        def get_delete_params(params, **kwargs):
            return {"StreamName": params["Name"], "EnforceConsumerDeletion": True}

        return {
            "create": {
                "function": "create_stream",
                "parameters": {"StreamName": "Name", "ShardCount": "ShardCount"},
                "defaults": {"ShardCount": 1},
            },
            "delete": {"function": "delete_stream", "parameters": get_delete_params},
        }


class KinesisStreamConsumer(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::StreamConsumer"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("ConsumerARN")

    def fetch_state(self, stack_name, resources):
        props = self.props
        stream_arn = self.resolve_refs_recursively(stack_name, props["StreamARN"], resources)
        result = aws_stack.connect_to_service("kinesis").list_stream_consumers(StreamARN=stream_arn)
        result = [r for r in result["Consumers"] if r["ConsumerName"] == props["ConsumerName"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {"function": "register_stream_consumer"},
            "delete": {"function": "deregister_stream_consumer"},
        }


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


class SFNStateMachine(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::StepFunctions::StateMachine"

    def get_resource_name(self):
        return self.props.get("StateMachineName")

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("stateMachineArn")

    def fetch_state(self, stack_name, resources):
        sm_name = self.props.get("StateMachineName") or self.resource_id
        sm_name = self.resolve_refs_recursively(stack_name, sm_name, resources)
        sfn_client = aws_stack.connect_to_service("stepfunctions")
        state_machines = sfn_client.list_state_machines()["stateMachines"]
        sm_arn = [m["stateMachineArn"] for m in state_machines if m["name"] == sm_name]
        if not sm_arn:
            return None
        result = sfn_client.describe_state_machine(stateMachineArn=sm_arn[0])
        return result

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("stepfunctions")
        sm_arn = self.props.get("stateMachineArn")
        if not sm_arn:
            self.state = self.fetch_state(stack_name=stack_name, resources=resources)
            sm_arn = self.state["stateMachineArn"]
        kwargs = {
            "stateMachineArn": sm_arn,
            "definition": props["DefinitionString"],
        }
        return client.update_state_machine(**kwargs)


class SFNActivity(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::StepFunctions::Activity"

    def fetch_state(self, stack_name, resources):
        activity_arn = self.physical_resource_id
        if not activity_arn:
            return None
        client = aws_stack.connect_to_service("stepfunctions")
        result = client.describe_activity(activityArn=activity_arn)
        return result


class CertificateManagerCertificate(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CertificateManager::Certificate"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("acm")
        result = client.list_certificates().get("CertificateSummaryList", [])
        domain_name = self.resolve_refs_recursively(
            stack_name, self.props.get("DomainName"), resources
        )
        result = [c for c in result if c["DomainName"] == domain_name]
        return (result or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("CertificateArn")

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(params, *args, **kwargs):
            result = select_attributes(
                params,
                [
                    "CertificateAuthorityArn",
                    "DomainName",
                    "DomainValidationOptions",
                    "SubjectAlternativeNames",
                    "Tags",
                    "ValidationMethod",
                ],
            )
            logging_pref = params.get("CertificateTransparencyLoggingPreference")
            if logging_pref:
                result["Options"] = {"CertificateTransparencyLoggingPreference": logging_pref}
            return result

        return {
            "create": {"function": "request_certificate", "parameters": _create_params},
            "delete": {
                "function": "delete_certificate",
                "parameters": ["CertificateArn"],
            },
        }


class IAMRole(GenericBaseModel, MotoRole):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Role"

    def get_resource_name(self):
        return self.props.get("RoleName")

    def fetch_state(self, stack_name, resources):
        role_name = self.resolve_refs_recursively(stack_name, self.props.get("RoleName"), resources)
        return aws_stack.connect_to_service("iam").get_role(RoleName=role_name)["Role"]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("iam")
        return client.update_role(
            RoleName=props.get("RoleName"), Description=props.get("Description") or ""
        )


class IAMPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::Policy"

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(self, stack_name, resources, managed_policy=False)

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name, *args, **kwargs):
            iam = aws_stack.connect_to_service("iam")
            props = resources[resource_id]["Properties"]
            cls.resolve_refs_recursively(stack_name, props, resources)
            policy_doc = json.dumps(remove_none_values(props["PolicyDocument"]))
            policy_name = props["PolicyName"]
            for role in props.get("Roles", []):
                iam.put_role_policy(
                    RoleName=role, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for user in props.get("Users", []):
                iam.put_user_policy(
                    UserName=user, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            for group in props.get("Groups", []):
                iam.put_group_policy(
                    GroupName=group, PolicyName=policy_name, PolicyDocument=policy_doc
                )
            return {}

        return {"create": {"function": _create}}

    @staticmethod
    def get_policy_state(obj, stack_name, resources, managed_policy=False):
        def _filter(pols):
            return [p for p in pols["AttachedPolicies"] if p["PolicyName"] == policy_name]

        iam = aws_stack.connect_to_service("iam")
        props = obj.props
        policy_name = props.get("PolicyName") or props.get("ManagedPolicyName")
        result = {}
        roles = props.get("Roles", [])
        users = props.get("Users", [])
        groups = props.get("Groups", [])
        if managed_policy:
            result["policy"] = iam.get_policy(PolicyArn=aws_stack.policy_arn(policy_name))
        for role in roles:
            role = obj.resolve_refs_recursively(stack_name, role, resources)
            policies = (
                _filter(iam.list_attached_role_policies(RoleName=role))
                if managed_policy
                else iam.get_role_policy(RoleName=role, PolicyName=policy_name)
            )
            result["role:%s" % role] = policies
        for user in users:
            user = obj.resolve_refs_recursively(stack_name, user, resources)
            policies = (
                _filter(iam.list_attached_user_policies(UserName=user))
                if managed_policy
                else iam.get_user_policy(UserName=user, PolicyName=policy_name)
            )
            result["user:%s" % user] = policies
        for group in groups:
            group = obj.resolve_refs_recursively(stack_name, group, resources)
            policies = (
                _filter(iam.list_attached_group_policies(GroupName=group))
                if managed_policy
                else iam.get_group_policy(GroupName=group, PolicyName=policy_name)
            )
            result["group:%s" % group] = policies
        result = {k: v for k, v in result.items() if v}
        return result or None


class IAMManagedPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::ManagedPolicy"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.role_arn(self.props["ManagedPolicyName"])

    def fetch_state(self, stack_name, resources):
        return IAMPolicy.get_policy_state(self, stack_name, resources, managed_policy=True)

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name, *args, **kwargs):
            iam = aws_stack.connect_to_service("iam")
            resource = resources[resource_id]
            props = resource["Properties"]
            cls.resolve_refs_recursively(stack_name, props, resources)
            policy_doc = json.dumps(props["PolicyDocument"])
            policy = iam.create_policy(
                PolicyName=props["ManagedPolicyName"], PolicyDocument=policy_doc
            )
            policy_arn = policy["Policy"]["Arn"]
            for role in resource.get("Roles", []):
                iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
            for user in resource.get("Users", []):
                iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)
            for group in resource.get("Groups", []):
                iam.attach_group_policy(GroupName=group, PolicyArn=policy_arn)
            return {}

        return {"create": {"function": _create}}


class GatewayResponse(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::GatewayResponse"

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        if not api_id:
            return
        client = aws_stack.connect_to_service("apigateway")
        result = client.get_gateway_response(restApiId=api_id, responseType=props["ResponseType"])
        return result if "responseType" in result else None


class GatewayRequestValidator(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::RequestValidator"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        name = self.resolve_refs_recursively(stack_name, props["Name"], resources)
        result = client.get_request_validators(restApiId=api_id).get("items", [])
        result = [r for r in result if r.get("name") == name]
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_request_validator",
                "parameters": {
                    "name": "Name",
                    "restApiId": "RestApiId",
                    "validateRequestBody": "ValidateRequestBody",
                    "validateRequestParameters": "ValidateRequestParameters",
                },
            },
            "delete": {
                "function": "delete_request_validator",
                "parameters": {"restApiId": "RestApiId", "requestValidatorId": "id"},
            },
        }


class GatewayRestAPI(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::RestApi"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        apis = aws_stack.connect_to_service("apigateway").get_rest_apis()["items"]
        api_name = self.props.get("Name") or self.resource_id
        api_name = self.resolve_refs_recursively(stack_name, api_name, resources)
        result = list(filter(lambda api: api["name"] == api_name, apis))
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def _api_id(params, resources, resource_id, **kwargs):
            resource = GatewayRestAPI(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        return {
            "create": {
                "function": "create_rest_api",
                "parameters": {"name": "Name", "description": "Description"},
            },
            "delete": {
                "function": "delete_rest_api",
                "parameters": {
                    "restApiId": _api_id,
                },
            },
        }


class GatewayDeployment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Deployment"

    def fetch_state(self, stack_name, resources):
        api_id = self.props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)

        if not api_id:
            return None

        result = aws_stack.connect_to_service("apigateway").get_deployments(restApiId=api_id)[
            "items"
        ]
        # TODO possibly filter results by stage name or other criteria

        return result[0] if result else None


class GatewayResource(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Resource"

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        parent_id = self.resolve_refs_recursively(stack_name, props.get("ParentId"), resources)

        if not api_id or not parent_id:
            return None

        api_resources = aws_stack.connect_to_service("apigateway").get_resources(restApiId=api_id)[
            "items"
        ]
        target_resource = list(
            filter(
                lambda res: res.get("parentId") == parent_id
                and res["pathPart"] == props["PathPart"],
                api_resources,
            )
        )

        if not target_resource:
            return None

        path = aws_stack.get_apigateway_path_for_resource(
            api_id, target_resource[0]["id"], resources=api_resources
        )
        result = list(filter(lambda res: res["path"] == path, api_resources))
        return result[0] if result else None


class GatewayMethod(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Method"

    def fetch_state(self, stack_name, resources):
        props = self.props

        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        res_id = self.resolve_refs_recursively(stack_name, props["ResourceId"], resources)
        if not api_id or not res_id:
            return None

        res_obj = aws_stack.connect_to_service("apigateway").get_resource(
            restApiId=api_id, resourceId=res_id
        )
        match = [
            v
            for (k, v) in res_obj.get("resourceMethods", {}).items()
            if props["HttpMethod"] in (v.get("httpMethod"), k)
        ]

        int_props = props.get("Integration") or {}
        if int_props.get("Type") == "AWS_PROXY":
            match = [
                m
                for m in match
                if m.get("methodIntegration", {}).get("type") == "AWS_PROXY"
                and m.get("methodIntegration", {}).get("httpMethod")
                == int_props.get("IntegrationHttpMethod")
            ]

        return match[0] if match else None

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("apigateway")
        integration = props.get("Integration")
        kwargs = {
            "restApiId": props["RestApiId"],
            "resourceId": props["ResourceId"],
            "httpMethod": props["HttpMethod"],
            "requestParameters": props.get("RequestParameters") or {},
        }
        if integration:
            kwargs["type"] = integration["Type"]
            if integration.get("IntegrationHttpMethod"):
                kwargs["integrationHttpMethod"] = integration.get("IntegrationHttpMethod")
            if integration.get("Uri"):
                kwargs["uri"] = integration.get("Uri")
            kwargs["requestParameters"] = integration.get("RequestParameters") or {}
            return client.put_integration(**kwargs)
        kwargs["authorizationType"] = props.get("AuthorizationType")

        return client.put_method(**kwargs)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        result = "%s-%s-%s" % (
            props.get("RestApiId"),
            props.get("ResourceId"),
            props.get("HttpMethod"),
        )
        return result


class GatewayStage(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Stage"

    def fetch_state(self, stack_name, resources):
        api_id = self.props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        if not api_id:
            return None
        result = aws_stack.connect_to_service("apigateway").get_stage(
            restApiId=api_id, stageName=self.props["StageName"]
        )
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    @staticmethod
    def get_deploy_templates():
        def get_params(params, **kwargs):
            result = keys_to_lower(params)
            param_names = [
                "restApiId",
                "stageName",
                "deploymentId",
                "description",
                "cacheClusterEnabled",
                "cacheClusterSize",
                "variables",
                "documentationVersion",
                "canarySettings",
                "tracingEnabled",
                "tags",
            ]
            result = select_attributes(result, param_names)
            result["tags"] = {t["key"]: t["value"] for t in result.get("tags", [])}
            return result

        return {"create": {"function": "create_stage", "parameters": get_params}}


class GatewayUsagePlan(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::UsagePlan"

    def fetch_state(self, stack_name, resources):
        plan_name = self.props.get("UsagePlanName")
        plan_name = self.resolve_refs_recursively(stack_name, plan_name, resources)
        result = aws_stack.connect_to_service("apigateway").get_usage_plans().get("items", [])
        result = [r for r in result if r["name"] == plan_name]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_usage_plan",
                "parameters": {
                    "name": "UsagePlanName",
                    "description": "Description",
                    "apiStages": lambda_keys_to_lower("ApiStages"),
                    "quota": lambda_keys_to_lower("Quota"),
                    "throttle": lambda_keys_to_lower("Throttle"),
                    "tags": params_list_to_dict("Tags"),
                },
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayApiKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::ApiKey"

    def fetch_state(self, stack_name, resources):
        props = self.props
        key_name = self.resolve_refs_recursively(stack_name, props.get("Name"), resources)
        cust_id = props.get("CustomerId")
        result = aws_stack.connect_to_service("apigateway").get_api_keys().get("items", [])
        result = [
            r
            for r in result
            if r.get("name") == key_name and cust_id in (None, r.get("customerId"))
        ]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_api_key",
                "parameters": {
                    "description": "Description",
                    "customerId": "CustomerId",
                    "name": "Name",
                    "value": "Value",
                    "enabled": "Enabled",
                    "stageKeys": lambda_keys_to_lower("StageKeys"),
                    "tags": params_list_to_dict("Tags"),
                },
                "types": {"enabled": bool},
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayUsagePlanKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::UsagePlanKey"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        key_id = self.resolve_refs_recursively(stack_name, self.props.get("KeyId"), resources)
        key_type = self.resolve_refs_recursively(stack_name, self.props.get("KeyType"), resources)
        plan_id = self.resolve_refs_recursively(
            stack_name, self.props.get("UsagePlanId"), resources
        )
        result = client.get_usage_plan_keys(usagePlanId=plan_id).get("items", [])
        result = [r for r in result if r["id"] == key_id and key_type in [None, r.get("type")]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_usage_plan_key",
                "parameters": lambda_keys_to_lower(),
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayModel(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Model"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        api_id = self.resolve_refs_recursively(stack_name, self.props["RestApiId"], resources)

        items = client.get_models(restApiId=api_id)["items"]
        if not items:
            return None

        model_name = self.resolve_refs_recursively(stack_name, self.props["Name"], resources)
        models = [item for item in items if item["name"] == model_name]
        if models:
            return models[0]

        return None


class GatewayAccount(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Account"


class S3Bucket(GenericBaseModel, FakeBucket):
    def get_resource_name(self):
        return self.normalize_bucket_name(self.props.get("BucketName"))

    @staticmethod
    def normalize_bucket_name(bucket_name):
        bucket_name = bucket_name or ""
        # AWS automatically converts upper to lower case chars in bucket names
        bucket_name = bucket_name.lower()
        return bucket_name

    @staticmethod
    def get_deploy_templates():
        def convert_acl_cf_to_s3(acl):
            """Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read')"""
            return re.sub("(?<!^)(?=[A-Z])", "-", acl).lower()

        def s3_bucket_notification_config(params, **kwargs):
            notif_config = params.get("NotificationConfiguration")
            if not notif_config:
                return None

            lambda_configs = []
            queue_configs = []
            topic_configs = []

            attr_tuples = (
                (
                    "LambdaConfigurations",
                    lambda_configs,
                    "LambdaFunctionArn",
                    "Function",
                ),
                ("QueueConfigurations", queue_configs, "QueueArn", "Queue"),
                ("TopicConfigurations", topic_configs, "TopicArn", "Topic"),
            )

            # prepare lambda/queue/topic notification configs
            for attrs in attr_tuples:
                for notif_cfg in notif_config.get(attrs[0]) or []:
                    filter_rules = notif_cfg.get("Filter", {}).get("S3Key", {}).get("Rules")
                    entry = {
                        attrs[2]: notif_cfg[attrs[3]],
                        "Events": [notif_cfg["Event"]],
                    }
                    if filter_rules:
                        entry["Filter"] = {"Key": {"FilterRules": filter_rules}}
                    attrs[1].append(entry)

            # construct final result
            result = {
                "Bucket": params.get("BucketName") or PLACEHOLDER_RESOURCE_NAME,
                "NotificationConfiguration": {
                    "LambdaFunctionConfigurations": lambda_configs,
                    "QueueConfigurations": queue_configs,
                    "TopicConfigurations": topic_configs,
                },
            }
            return result

        def get_bucket_location_config(**kwargs):
            region = aws_stack.get_region()
            if region == AWS_REGION_US_EAST_1:
                return None
            return {"LocationConstraint": region}

        result = {
            "create": [
                {
                    "function": "create_bucket",
                    "parameters": {
                        "Bucket": ["BucketName", PLACEHOLDER_RESOURCE_NAME],
                        "ACL": lambda params, **kwargs: convert_acl_cf_to_s3(
                            params.get("AccessControl", "PublicRead")
                        ),
                        "CreateBucketConfiguration": lambda params, **kwargs: get_bucket_location_config(),
                    },
                },
                {
                    "function": "put_bucket_notification_configuration",
                    "parameters": s3_bucket_notification_config,
                },
            ],
            "delete": [{"function": "delete_bucket", "parameters": {"Bucket": "BucketName"}}],
        }
        return result

    def fetch_state(self, stack_name, resources):
        props = self.props
        bucket_name = props.get("BucketName") or self.resource_id
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        bucket_name = self.normalize_bucket_name(bucket_name)
        s3_client = aws_stack.connect_to_service("s3")
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        notifs = props.get("NotificationConfiguration")
        if not response or not notifs:
            return response
        configs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        has_notifs = (
            configs.get("TopicConfigurations")
            or configs.get("QueueConfigurations")
            or configs.get("LambdaFunctionConfigurations")
        )
        if notifs and not has_notifs:
            return None
        return response

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in ["DomainName", "RegionalDomainName"]:
            return LOCALHOST
        return super(S3Bucket, self).get_cfn_attribute(attribute_name)


class S3BucketPolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::S3::BucketPolicy"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        policy = self.props.get("Policy")
        return policy and md5(canonical_json(json.loads(policy)))

    def fetch_state(self, stack_name, resources):
        bucket_name = self.props.get("Bucket") or self.resource_id
        bucket_name = self.resolve_refs_recursively(stack_name, bucket_name, resources)
        return aws_stack.connect_to_service("s3").get_bucket_policy(Bucket=bucket_name)


class CloudWatchAlarm(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudWatch::Alarm"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("AlarmName")

    def _response_name(self):
        return "MetricAlarms"

    @classmethod
    def _create_function_name(self):
        return "put_metric_alarm"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("cloudwatch")
        alarm_name = self.resolve_refs_recursively(stack_name, self.props["AlarmName"], resources)
        result = client.describe_alarms(AlarmNames=[alarm_name]).get(self._response_name(), [])
        return (result or [None])[0]

    @classmethod
    def get_deploy_templates(cls):
        def get_delete_params(params, **kwargs):
            return {"AlarmNames": [params["AlarmName"]]}

        return {
            "create": {"function": cls._create_function_name()},
            "delete": {"function": "delete_alarms", "parameters": get_delete_params},
        }


class CloudWatchCompositeAlarm(CloudWatchAlarm):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudWatch::CompositeAlarm"

    def _response_name(self):
        return "CompositeAlarms"

    @classmethod
    def _create_function_name(self):
        return "put_composite_alarm"


class SQSQueue(GenericBaseModel, MotoQueue):
    @staticmethod
    def cloudformation_type():
        return "AWS::SQS::Queue"

    def get_resource_name(self):
        return self.props.get("QueueName")

    def get_physical_resource_id(self, attribute=None, **kwargs):
        queue_url = None
        props = self.props
        try:
            queue_url = aws_stack.get_sqs_queue_url(props.get("QueueName"))
        except Exception as e:
            if "NonExistentQueue" in str(e):
                raise DependencyNotYetSatisfied(
                    resource_ids=self.resource_id, message="Unable to get queue: %s" % e
                )
        if attribute == "Arn":
            return aws_stack.sqs_queue_arn(props.get("QueueName"))
        return queue_url

    def fetch_state(self, stack_name, resources):
        queue_name = self.resolve_refs_recursively(stack_name, self.props["QueueName"], resources)
        sqs_client = aws_stack.connect_to_service("sqs")
        queues = sqs_client.list_queues()
        result = list(
            filter(
                lambda item:
                # TODO possibly find a better way to compare resource_id with queue URLs
                item.endswith("/%s" % queue_name),
                queues.get("QueueUrls", []),
            )
        )
        if not result:
            return None
        result = sqs_client.get_queue_attributes(QueueUrl=result[0], AttributeNames=["All"])[
            "Attributes"
        ]
        result["Arn"] = result["QueueArn"]
        return result

    @staticmethod
    def get_deploy_templates():
        def _queue_url(params, resources, resource_id, **kwargs):
            resource = SQSQueue(resources[resource_id])
            props = resource.props
            queue_url = resource.physical_resource_id or props.get("QueueUrl")
            if queue_url:
                return queue_url
            return aws_stack.sqs_queue_url_for_arn(props["QueueArn"])

        return {
            "create": {
                "function": "create_queue",
                "parameters": {
                    "QueueName": ["QueueName", PLACEHOLDER_RESOURCE_NAME],
                    "Attributes": params_select_attributes(
                        "ContentBasedDeduplication",
                        "DelaySeconds",
                        "FifoQueue",
                        "MaximumMessageSize",
                        "MessageRetentionPeriod",
                        "VisibilityTimeout",
                        "RedrivePolicy",
                        "ReceiveMessageWaitTimeSeconds",
                    ),
                    "tags": params_list_to_dict("Tags"),
                },
            },
            "delete": {
                "function": "delete_queue",
                "parameters": {"QueueUrl": _queue_url},
            },
        }


class SNSTopic(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Topic"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.sns_topic_arn(self.props["TopicName"])

    def fetch_state(self, stack_name, resources):
        topic_name = self.resolve_refs_recursively(stack_name, self.props["TopicName"], resources)
        topics = aws_stack.connect_to_service("sns").list_topics()
        result = list(
            filter(
                lambda item: item["TopicArn"].split(":")[-1] == topic_name,
                topics.get("Topics", []),
            )
        )
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def _topic_arn(params, resources, resource_id, **kwargs):
            resource = SNSTopic(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        return {
            "create": {
                "function": "create_topic",
                "parameters": {"Name": "TopicName", "Tags": "Tags"},
            },
            "delete": {
                "function": "delete_topic",
                "parameters": {"TopicArn": _topic_arn},
            },
        }


class SNSSubscription(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Subscription"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("SubscriptionArn")

    def fetch_state(self, stack_name, resources):
        props = self.props
        topic_arn = props.get("TopicArn")
        topic_arn = self.resolve_refs_recursively(stack_name, topic_arn, resources)
        if topic_arn is None:
            return
        subs = aws_stack.connect_to_service("sns").list_subscriptions_by_topic(TopicArn=topic_arn)
        result = [
            sub
            for sub in subs["Subscriptions"]
            if props.get("Protocol") == sub["Protocol"] and props.get("Endpoint") == sub["Endpoint"]
        ]
        # TODO: use get_subscription_attributes to compare FilterPolicy
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def sns_subscription_arn(params, resources, resource_id, **kwargs):
            resource = resources[resource_id]
            return resource["PhysicalResourceId"]

        def sns_subscription_params(params, **kwargs):
            def attr_val(val):
                return json.dumps(val) if isinstance(val, (dict, list)) else str(val)

            attrs = [
                "DeliveryPolicy",
                "FilterPolicy",
                "RawMessageDelivery",
                "RedrivePolicy",
            ]
            result = dict([(a, attr_val(params[a])) for a in attrs if a in params])
            return result

        return {
            "create": {
                "function": "subscribe",
                "parameters": {
                    "TopicArn": "TopicArn",
                    "Protocol": "Protocol",
                    "Endpoint": "Endpoint",
                    "Attributes": sns_subscription_params,
                },
            },
            "delete": {
                "function": "unsubscribe",
                "parameters": {"SubscriptionArn": sns_subscription_arn},
            },
        }


class QueuePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SQS::QueuePolicy"

    # TODO: add deployment methods


class DynamoDBTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::DynamoDB::Table"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        table_name = self.props.get("TableName")
        if attribute in REF_ID_ATTRS:
            return table_name
        return aws_stack.dynamodb_table_arn(table_name)

    def fetch_state(self, stack_name, resources):
        table_name = self.props.get("TableName") or self.resource_id
        table_name = self.resolve_refs_recursively(stack_name, table_name, resources)
        return aws_stack.connect_to_service("dynamodb").describe_table(TableName=table_name)


class RedshiftCluster(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Redshift::Cluster"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("ClusterIdentifier")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("redshift")
        cluster_id = self.resolve_refs_recursively(
            stack_name, self.props.get("ClusterIdentifier"), resources
        )
        result = client.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {"create": {"function": "create_cluster"}}


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::Parameter"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name") or self.resource_id

    def fetch_state(self, stack_name, resources):
        param_name = self.props.get("Name") or self.resource_id
        param_name = self.resolve_refs_recursively(stack_name, param_name, resources)
        return aws_stack.connect_to_service("ssm").get_parameter(Name=param_name)["Parameter"]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_parameter",
                "parameters": merge_parameters(
                    params_dict_to_list("Tags", wrapper="Tags"),
                    select_parameters(
                        "Name",
                        "Type",
                        "Value",
                        "Description",
                        "AllowedPattern",
                        "Policies",
                        "Tier",
                    ),
                ),
                "types": {"Value": str},
            }
        }


class SecretsManagerSecret(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::Secret"

    def get_physical_resource_id(self, attribute, **kwargs):
        props = self.props
        result = props.get("Arn") or aws_stack.secretsmanager_secret_arn(props["Name"])
        return result

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in (REF_ARN_ATTRS + REF_ID_ATTRS):
            return self.get_physical_resource_id(attribute_name)
        return super(SecretsManagerSecret, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        secret_name = self.props.get("Name") or self.resource_id
        secret_name = self.resolve_refs_recursively(stack_name, secret_name, resources)
        result = aws_stack.connect_to_service("secretsmanager").describe_secret(
            SecretId=secret_name
        )
        return result

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_secret",
                "parameters": lambda_select_params(
                    "Name", "Description", "KmsKeyId", "SecretString", "Tags"
                ),
            },
            "delete": {"function": "delete_secret", "parameters": {"SecretId": "Name"}},
        }


class SecretsManagerSecretTargetAttachment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::SecretTargetAttachment"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerRotationSchedule(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::RotationSchedule"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        # TODO implement?
        return {"state": "dummy"}


class SecretsManagerResourcePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SecretsManager::ResourcePolicy"

    def get_physical_resource_id(self, attribute, **kwargs):
        return aws_stack.secretsmanager_secret_arn(self.props.get("SecretId"))

    def fetch_state(self, stack_name, resources):
        secret_id = self.resolve_refs_recursively(stack_name, self.props.get("SecretId"), resources)
        result = aws_stack.connect_to_service("secretsmanager").get_resource_policy(
            SecretId=secret_id
        )
        return result

    @staticmethod
    def get_deploy_templates():
        def create_params(params, **kwargs):
            return {
                "SecretId": params["SecretId"].split(":")[-1],
                "ResourcePolicy": json.dumps(params["ResourcePolicy"]),
                "BlockPublicPolicy": params.get("BlockPublicPolicy"),
            }

        return {
            "create": {"function": "put_resource_policy", "parameters": create_params},
            "delete": {
                "function": "delete_resource_policy",
                "parameters": {"SecretId": "SecretId"},
            },
        }


class KMSKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Key"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("kms")
        physical_res_id = self.physical_resource_id
        props = self.props
        res_tags = props.get("Tags", [])
        if not physical_res_id:
            # TODO: find a more efficient approach for this?
            for key in client.list_keys()["Keys"]:
                details = client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                tags = client.list_resource_tags(KeyId=key["KeyId"]).get("Tags", [])
                tags = [{"Key": tag["TagKey"], "Value": tag["TagValue"]} for tag in tags]
                if (
                    tags == res_tags
                    and details.get("Description") == props.get("Description")
                    and props.get("KeyUsage") in [None, details.get("KeyUsage")]
                ):
                    physical_res_id = key["KeyId"]
                    # TODO should this be removed from here? It seems that somewhere along the execution
                    # chain the 'PhysicalResourceId' gets overwritten with None, hence setting it here
                    self.resource_json["PhysicalResourceId"] = physical_res_id
                    break
        if not physical_res_id:
            return
        return client.describe_key(KeyId=physical_res_id)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute in REF_ID_ATTRS:
            return self.physical_resource_id
        return self.physical_resource_id and aws_stack.kms_key_arn(self.physical_resource_id)

    @staticmethod
    def get_deploy_templates():
        def create_params(params, **kwargs):
            return {
                "Policy": params.get("KeyPolicy"),
                "Tags": [
                    {"TagKey": tag["Key"], "TagValue": tag["Value"]}
                    for tag in params.get("Tags", [])
                ],
            }

        return {
            "create": {"function": "create_key", "parameters": create_params},
            "delete": {
                # TODO Key needs to be deleted in KMS backend
                "function": "schedule_key_deletion",
                "parameters": {"KeyId": "PhysicalResourceId"},
            },
        }


class KMSAlias(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::KMS::Alias"

    def fetch_state(self, stack_name, resources):
        kms = aws_stack.connect_to_service("kms")
        aliases = kms.list_aliases()["Aliases"]
        for alias in aliases:
            if alias["AliasName"] == self.props.get("AliasName"):
                return alias

        return None

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_alias",
                "parameters": {"AliasName": "AliasName", "TargetKeyId": "TargetKeyId"},
            },
            "delete": {
                "function": "delete_alias",
                "parameters": {"AliasName": "AliasName"},
            },
        }


class EC2Instance(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::Instance"

    def fetch_state(self, stack_name, resources):
        instance_id = self.physical_resource_id
        if not instance_id:
            return None
        client = aws_stack.connect_to_service("ec2")
        resp = client.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]

    def update_resource(self, new_resource, stack_name, resources):
        instance_id = new_resource["PhysicalResourceId"]
        props = new_resource["Properties"]
        groups = props.get("SecurityGroups", props.get("SecurityGroupIds"))

        client = aws_stack.connect_to_service("ec2")
        client.modify_instance_attribute(
            Attribute="instanceType",
            Groups=groups,
            InstanceId=instance_id,
            InstanceType={"Value": props["InstanceType"]},
        )
        resp = client.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]


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

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_vpc",
                "parameters": {
                    "CidrBlock": "CidrBlock",
                    "InstanceTenancy": "InstanceTenancy"
                    # TODO: add TagSpecifications
                },
            },
            "delete": {
                "function": "delete_vpc",
                "parameters": {"VpcId": "PhysicalResourceId"},
            },
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


class InstanceProfile(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::IAM::InstanceProfile"

    def fetch_state(self, stack_name, resources):
        instance_profile_name = self.get_physical_resource_id()
        if not instance_profile_name:
            return None
        client = aws_stack.connect_to_service("iam")
        resp = client.get_instance_profile(InstanceProfileName=instance_profile_name)
        return resp["InstanceProfile"]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id or self.props.get("InstanceProfileName")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_instance_profile",
                "parameters": {
                    "InstanceProfileName": "InstanceProfileName",
                    "Path": "Path",
                },
            },
            "delete": {
                "function": "delete_instance_profile",
                "parameters": {"InstanceProfileName": "InstanceProfileName"},
            },
        }


class EC2RouteTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::EC2::RouteTable"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("ec2")
        route_tables = client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [self.props["VpcId"]]},
                {"Name": "association.main", "Values": ["false"]},
            ]
        )["RouteTables"]
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
        if route_table:
            associations = route_table.get("Associations", [])
            association = [a for a in associations if a.get("GatewayId") == gw_id]
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
            }
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


class ResourceGroupsGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ResourceGroups::Group"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("resource-groups")
        result = client.list_groups().get("Groups", [])
        result = [g for g in result if g["Name"] == self.props["Name"]]
        return (result or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute in REF_ARN_ATTRS:
            return self.props.get("GroupArn")
        return self.props.get("Name")

    @classmethod
    def get_deploy_templates(cls):
        return {
            "create": {
                "function": "create_group",
                "parameters": {
                    "Name": "Name",
                    "Description": "Description",
                    "ResourceQuery": "ResourceQuery",
                    "Configuration": "Configuration",
                    "Tags": params_list_to_dict("Tags"),
                },
            },
            "delete": {"function": "delete_group", "parameters": {"Group": "Name"}},
        }
