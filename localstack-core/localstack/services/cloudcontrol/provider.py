import json
import logging

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.cloudcontrol import (
    CloudcontrolApi,
    GetResourceOutput,
    HandlerNextToken,
    Identifier,
    ListResourcesOutput,
    MaxResults,
    Properties,
    ResourceDescription,
    RoleArn,
    TypeName,
    TypeVersionId,
)
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.resource_provider import (
    PRO_RESOURCE_PROVIDERS,
    NoResourceProvider,
    ResourceProvider,
    ResourceRequest,
    plugin_manager,
    pro_plugin_manager,
)

LOG = logging.getLogger(__name__)


def load_resource_provider(resource_type: str) -> ResourceProvider:
    # TODO: unify namespace of plugins

    # 1. try to load pro resource provider
    # prioritise pro resource providers
    if PRO_RESOURCE_PROVIDERS:
        try:
            plugin = pro_plugin_manager.load(resource_type)
            return plugin.factory()
        except ValueError:
            # could not find a plugin for that name
            pass
        except Exception:
            LOG.warning(
                "Failed to load PRO resource type %s as a ResourceProvider.",
                resource_type,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )

    # 2. try to load community resource provider
    try:
        plugin = plugin_manager.load(resource_type)
        return plugin.factory()
    except ValueError:
        # could not find a plugin for that name
        pass
    except Exception:
        if config.CFN_VERBOSE_ERRORS:
            LOG.warning(
                "Failed to load community resource type %s as a ResourceProvider.",
                resource_type,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )

    raise NoResourceProvider


def determine_id_based_on_type(type_name, props):
    # TODO: do this properly based on schema
    # cheating
    match type_name:
        # TODO: dynamodb
        # TODO: secretsmanager
        # TODO: iam
        # TODO: cloudformation
        # TODO: ssm
        # TODO: ec2
        case "AWS::DynamoDB::Table":
            return props["TableName"]
        case "AWS::SecretsManager::Secret":
            return props["Id"]
        case "AWS::IAM::Role":
            return props["RoleName"]
        case "AWS::CloudFormation::Stack":
            return props["Id"]
        case "AWS::SSM::Parameter":
            return props["Id"]
        case "AWS::EC2::VPC":
            return props["VpcId"]
        case "AWS::SNS::Topic":
            return props["TopicArn"]
        case "AWS::SQS::Queue":
            return props["QueueUrl"]
        case "AWS::Lambda::Function":
            return props["FunctionName"]
        case _:
            return "?"


class CloudControlProvider(CloudcontrolApi):
    def get_resource(
        self,
        context: RequestContext,
        type_name: TypeName,
        identifier: Identifier,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        **kwargs,
    ) -> GetResourceOutput:
        return GetResourceOutput(
            TypeName=type_name,
            ResourceDescription=ResourceDescription(Identifier=identifier, Properties=""),
        )

    def list_resources(
        self,
        context: RequestContext,
        type_name: TypeName,
        type_version_id: TypeVersionId = None,
        role_arn: RoleArn = None,
        next_token: HandlerNextToken = None,
        max_results: MaxResults = None,
        resource_model: Properties = None,
        **kwargs,
    ) -> ListResourcesOutput:
        provider = load_resource_provider(type_name)
        client_factory = connect_to(
            region_name=context.region,
        )
        # state handling is still a bit unclear
        event = provider.list(
            ResourceRequest(
                aws_client_factory=client_factory,
                resource_type=type_name,
                account_id="",
                desired_state={},
                previous_state={},
                region_name="",
                action="",
                logical_resource_id="",
                custom_context={},
                stack_name="",
                stack_id="",
                _original_payload={},
                request_token="",
                logger=LOG,
            )
        )
        return ListResourcesOutput(
            TypeName=type_name,
            ResourceDescriptions=[
                # identifier needs to again be determined from schema here, properties can be taken direclty
                ResourceDescription(
                    Identifier=determine_id_based_on_type(type_name, props),
                    Properties=json.dumps(props),
                )
                for props in event.resource_models
            ],
        )
