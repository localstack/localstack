import json
import logging
import re

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
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.resource_provider import (
    NoResourceProvider,
    ResourceProvider,
    ResourceRequest,
    plugin_manager,
    resolve_json_pointer,
)

LOG = logging.getLogger(__name__)


def extract_physical_resource_id_from_model_with_schema(
    resource_model: Properties, resource_type: str, resource_type_schema: dict
) -> str:
    if resource_type in PHYSICAL_RESOURCE_ID_SPECIAL_CASES:
        primary_id_path = PHYSICAL_RESOURCE_ID_SPECIAL_CASES[resource_type]

        if "<" in primary_id_path:
            # composite quirk, e.g. something like MyRef|MyName
            # try to extract parts
            physical_resource_id = primary_id_path
            find_results = re.findall("<([^>]+)>", primary_id_path)
            for found_part in find_results:
                resolved_part = resolve_json_pointer(resource_model, found_part)
                physical_resource_id = physical_resource_id.replace(
                    f"<{found_part}>", resolved_part
                )
        else:
            physical_resource_id = resolve_json_pointer(resource_model, primary_id_path)
    else:
        primary_id_paths = resource_type_schema["primaryIdentifier"]
        if len(primary_id_paths) > 1:
            # TODO: auto-merge. Verify logic here with AWS
            physical_resource_id = "-".join(
                [resolve_json_pointer(resource_model, pip) for pip in primary_id_paths]
            )
        else:
            physical_resource_id = resolve_json_pointer(resource_model, primary_id_paths[0])

    return physical_resource_id


def load_resource_provider(resource_type: str) -> ResourceProvider:
    # TODO: unify namespace of plugins
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
                    Identifier=extract_physical_resource_id_from_model_with_schema(
                        props, type_name, provider.SCHEMA
                    ),
                    Properties=json.dumps(props),
                )
                for props in event.resource_models
            ],
        )
