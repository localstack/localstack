import base64
import dataclasses
import datetime
import json
import logging
import os
import threading
import time
from typing import IO, Optional, Tuple

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import RequestContext, ServiceException, handler
from localstack.aws.api.lambda_ import (
    AccountLimit,
    AccountUsage,
    AddLayerVersionPermissionResponse,
    AddPermissionRequest,
    AddPermissionResponse,
    Alias,
    AliasConfiguration,
    AliasRoutingConfiguration,
    AllowedPublishers,
    Architecture,
    Arn,
    Blob,
    BlobStream,
    CodeSigningConfigArn,
    CodeSigningConfigNotFoundException,
    CodeSigningPolicies,
    CompatibleArchitectures,
    CompatibleRuntimes,
    Concurrency,
    Cors,
    CreateCodeSigningConfigResponse,
    CreateEventSourceMappingRequest,
    CreateFunctionRequest,
    CreateFunctionUrlConfigResponse,
    DeleteCodeSigningConfigResponse,
    Description,
    DestinationConfig,
    EventSourceMappingConfiguration,
    FunctionArn,
    FunctionCodeLocation,
    FunctionConfiguration,
    FunctionEventInvokeConfig,
    FunctionName,
    FunctionUrlAuthType,
    FunctionUrlQualifier,
)
from localstack.aws.api.lambda_ import FunctionVersion as FunctionVersionApi
from localstack.aws.api.lambda_ import (
    GetAccountSettingsResponse,
    GetCodeSigningConfigResponse,
    GetFunctionCodeSigningConfigResponse,
    GetFunctionConcurrencyResponse,
    GetFunctionResponse,
    GetFunctionUrlConfigResponse,
    GetLayerVersionPolicyResponse,
    GetLayerVersionResponse,
    GetPolicyResponse,
    GetProvisionedConcurrencyConfigResponse,
    InvalidParameterValueException,
    InvocationResponse,
    InvocationType,
    InvokeAsyncResponse,
    InvokeMode,
    LambdaApi,
    LastUpdateStatus,
    LayerName,
    LayerPermissionAllowedAction,
    LayerPermissionAllowedPrincipal,
    LayersListItem,
    LayerVersionArn,
    LayerVersionContentInput,
    LayerVersionNumber,
    LicenseInfo,
    ListAliasesResponse,
    ListCodeSigningConfigsResponse,
    ListEventSourceMappingsResponse,
    ListFunctionEventInvokeConfigsResponse,
    ListFunctionsByCodeSigningConfigResponse,
    ListFunctionsResponse,
    ListFunctionUrlConfigsResponse,
    ListLayersResponse,
    ListLayerVersionsResponse,
    ListProvisionedConcurrencyConfigsResponse,
    ListTagsResponse,
    ListVersionsByFunctionResponse,
    LogType,
    MasterRegion,
    MaxFunctionEventInvokeConfigListItems,
    MaximumEventAgeInSeconds,
    MaximumRetryAttempts,
    MaxItems,
    MaxLayerListItems,
    MaxListItems,
    MaxProvisionedConcurrencyConfigListItems,
    NamespacedFunctionName,
    NamespacedStatementId,
    OnFailure,
    OnSuccess,
    OrganizationId,
    PackageType,
    PositiveInteger,
    PreconditionFailedException,
    ProvisionedConcurrencyConfigListItem,
    ProvisionedConcurrencyConfigNotFoundException,
    ProvisionedConcurrencyStatusEnum,
    PublishLayerVersionResponse,
    PutFunctionCodeSigningConfigResponse,
    PutProvisionedConcurrencyConfigResponse,
    Qualifier,
    ReservedConcurrentExecutions,
    ResourceConflictException,
    ResourceNotFoundException,
    Runtime,
    RuntimeVersionConfig,
)
from localstack.aws.api.lambda_ import ServiceException as LambdaServiceException
from localstack.aws.api.lambda_ import (
    SnapStart,
    SnapStartApplyOn,
    SnapStartOptimizationStatus,
    SnapStartResponse,
    State,
    StatementId,
    StateReasonCode,
    String,
    TagKeyList,
    Tags,
    TracingMode,
    UpdateCodeSigningConfigResponse,
    UpdateEventSourceMappingRequest,
    UpdateFunctionCodeRequest,
    UpdateFunctionConfigurationRequest,
    UpdateFunctionUrlConfigResponse,
    Version,
)
from localstack.aws.connect import connect_to
from localstack.services.edge import ROUTER
from localstack.services.lambda_ import api_utils
from localstack.services.lambda_ import hooks as lambda_hooks
from localstack.services.lambda_.api_utils import ARCHITECTURES, STATEMENT_ID_REGEX
from localstack.services.lambda_.event_source_listeners.event_source_listener import (
    EventSourceListener,
)
from localstack.services.lambda_.invocation import AccessDeniedException
from localstack.services.lambda_.invocation.execution_environment import (
    EnvironmentStartupTimeoutException,
)
from localstack.services.lambda_.invocation.lambda_models import (
    IMAGE_MAPPING,
    SNAP_START_SUPPORTED_RUNTIMES,
    AliasRoutingConfig,
    CodeSigningConfig,
    EventInvokeConfig,
    Function,
    FunctionResourcePolicy,
    FunctionUrlConfig,
    FunctionVersion,
    ImageConfig,
    LambdaEphemeralStorage,
    Layer,
    LayerPolicy,
    LayerPolicyStatement,
    LayerVersion,
    ProvisionedConcurrencyConfiguration,
    RequestEntityTooLargeException,
    ResourcePolicy,
    UpdateStatus,
    ValidationException,
    VersionAlias,
    VersionFunctionConfiguration,
    VersionIdentifier,
    VersionState,
    VpcConfig,
)
from localstack.services.lambda_.invocation.lambda_service import (
    LambdaService,
    create_image_code,
    destroy_code_if_not_used,
    lambda_stores,
    store_lambda_archive,
    store_s3_bucket_archive,
)
from localstack.services.lambda_.invocation.models import LambdaStore
from localstack.services.lambda_.invocation.runtime_executor import get_runtime_executor
from localstack.services.lambda_.lambda_utils import validate_filters
from localstack.services.lambda_.layerfetcher.layer_fetcher import LayerFetcher
from localstack.services.lambda_.urlrouter import FunctionUrlRouter
from localstack.services.plugins import ServiceLifecycleHook
from localstack.state import StateVisitor
from localstack.utils.aws.arns import extract_service_from_arn
from localstack.utils.collections import PaginatedList
from localstack.utils.files import load_file
from localstack.utils.strings import get_random_hex, long_uid, short_uid, to_bytes, to_str
from localstack.utils.sync import poll_condition
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128

LAMBDA_TAG_LIMIT_PER_RESOURCE = 50
LAMBDA_LAYERS_LIMIT_PER_FUNCTION = 5


class LambdaProvider(LambdaApi, ServiceLifecycleHook):
    lambda_service: LambdaService
    create_fn_lock: threading.RLock
    create_layer_lock: threading.RLock
    router: FunctionUrlRouter
    layer_fetcher: LayerFetcher | None

    def __init__(self) -> None:
        self.lambda_service = LambdaService()
        self.create_fn_lock = threading.RLock()
        self.create_layer_lock = threading.RLock()
        self.router = FunctionUrlRouter(ROUTER, self.lambda_service)
        self.layer_fetcher = None
        lambda_hooks.inject_layer_fetcher.run(self)

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(lambda_stores)

    def on_before_state_reset(self):
        self.lambda_service.stop()

    def on_after_state_reset(self):
        self.router.lambda_service = self.lambda_service = LambdaService()

    def on_before_state_load(self):
        self.lambda_service.stop()

    def on_after_state_load(self):
        self.lambda_service = LambdaService()
        self.router.lambda_service = self.lambda_service

        # TODO: provisioned concurrency
        for account_id, account_bundle in lambda_stores.items():
            for region_name, state in account_bundle.items():
                for fn in state.functions.values():
                    for fn_version in fn.versions.values():
                        # restore the "Pending" state for every function version and start it
                        try:
                            new_state = VersionState(
                                state=State.Pending,
                                code=StateReasonCode.Creating,
                                reason="The function is being created.",
                            )
                            new_config = dataclasses.replace(fn_version.config, state=new_state)
                            new_version = dataclasses.replace(fn_version, config=new_config)
                            fn.versions[fn_version.id.qualifier] = new_version
                            self.lambda_service.create_function_version(fn_version).result(
                                timeout=5
                            )
                        except Exception:
                            LOG.warning(
                                "Failed to restore function version %s",
                                fn_version.id.qualified_arn(),
                                exc_info=True,
                            )

                # Restore event source listeners
                for esm in state.event_source_mappings.values():
                    EventSourceListener.start_listeners_for_asf(esm, self.lambda_service)

    def on_after_init(self):
        self.router.register_routes()
        get_runtime_executor().validate_environment()

    def on_before_stop(self) -> None:
        # TODO: should probably unregister routes?
        self.lambda_service.stop()

    @staticmethod
    def _get_function(function_name: str, account_id: str, region: str) -> Function:
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        if not function:
            arn = api_utils.unqualified_lambda_arn(
                function_name=function_name,
                account=account_id,
                region=region,
            )
            raise ResourceNotFoundException(
                f"Function not found: {arn}",
                Type="User",
            )
        return function

    @staticmethod
    def _get_function_version(
        function_name: str, qualifier: str | None, account_id: str, region: str
    ) -> FunctionVersion:
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        qualifier_or_latest = qualifier or "$LATEST"
        version = function and function.versions.get(qualifier_or_latest)
        if not function or not version:
            arn = api_utils.lambda_arn(
                function_name=function_name,
                qualifier=qualifier,
                account=account_id,
                region=region,
            )
            raise ResourceNotFoundException(
                f"Function not found: {arn}",
                Type="User",
            )
        # TODO what if version is missing?
        return version

    @staticmethod
    def _validate_qualifier_expression(qualifier: str) -> None:
        if not api_utils.is_qualifier_expression(qualifier):
            raise ValidationException(
                f"1 validation error detected: Value '{qualifier}' at 'qualifier' failed to satisfy constraint: "
                f"Member must satisfy regular expression pattern: (|[a-zA-Z0-9$_-]+)"
            )

    @staticmethod
    def _resolve_fn_qualifier(resolved_fn: Function, qualifier: str | None) -> tuple[str, str]:
        """Attempts to resolve a given qualifier and returns a qualifier that exists or
        raises an appropriate ResourceNotFoundException.

        :param resolved_fn: The resolved lambda function
        :param qualifier: The qualifier to be resolved or None
        :return: Tuple of (resolved qualifier, function arn either qualified or unqualified)"""
        function_name = resolved_fn.function_name
        # assuming function versions need to live in the same account and region
        account_id = resolved_fn.latest().id.account
        region = resolved_fn.latest().id.region
        fn_arn = api_utils.unqualified_lambda_arn(function_name, account_id, region)
        if qualifier is not None:
            fn_arn = api_utils.qualified_lambda_arn(function_name, qualifier, account_id, region)
            if api_utils.qualifier_is_alias(qualifier):
                if qualifier not in resolved_fn.aliases:
                    raise ResourceNotFoundException(f"Cannot find alias arn: {fn_arn}", Type="User")
            elif api_utils.qualifier_is_version(qualifier) or qualifier == "$LATEST":
                if qualifier not in resolved_fn.versions:
                    raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")
            else:
                # matches qualifier pattern but invalid alias or version
                raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")
        resolved_qualifier = qualifier or "$LATEST"
        return resolved_qualifier, fn_arn

    @staticmethod
    def _function_revision_id(resolved_fn: Function, resolved_qualifier: str) -> str:
        if api_utils.qualifier_is_alias(resolved_qualifier):
            return resolved_fn.aliases[resolved_qualifier].revision_id
        # Assumes that a non-alias is a version
        else:
            return resolved_fn.versions[resolved_qualifier].config.revision_id

    def _resolve_vpc_id(self, subnet_id: str) -> str:
        return connect_to().ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["VpcId"]

    def _build_vpc_config(
        self,
        vpc_config: Optional[dict] = None,
    ) -> VpcConfig | None:
        if not vpc_config:
            return None

        subnet_ids = vpc_config.get("SubnetIds", [])
        if subnet_ids is not None and len(subnet_ids) == 0:
            return VpcConfig(vpc_id="", security_group_ids=[], subnet_ids=[])

        return VpcConfig(
            vpc_id=self._resolve_vpc_id(subnet_ids[0]),
            security_group_ids=vpc_config.get("SecurityGroupIds", []),
            subnet_ids=subnet_ids,
        )

    def _create_version_model(
        self,
        function_name: str,
        region: str,
        account_id: str,
        description: str | None = None,
        revision_id: str | None = None,
        code_sha256: str | None = None,
    ) -> tuple[FunctionVersion, bool]:
        """
        Release a new version to the model if all restrictions are met.
        Restrictions:
          - CodeSha256, if provided, must equal the current latest version code hash
          - RevisionId, if provided, must equal the current latest version revision id
          - Some changes have been done to the latest version since last publish
        Will return a tuple of the version, and whether the version was published (True) or the latest available version was taken (False).
        This can happen if the latest version has not been changed since the last version publish, in this case the last version will be returned.

        :param function_name: Function name to be published
        :param region: Region of the function
        :param account_id: Account of the function
        :param description: new description of the version (will be the description of the function if missing)
        :param revision_id: Revision id, function will raise error if it does not match latest revision id
        :param code_sha256: Code sha256, function will raise error if it does not match latest code hash
        :return: Tuple of (published version, whether version was released or last released version returned, since nothing changed)
        """
        current_latest_version = self._get_function_version(
            function_name=function_name, qualifier="$LATEST", account_id=account_id, region=region
        )
        if revision_id and current_latest_version.config.revision_id != revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )

        # check if code hashes match if they are specified
        current_hash = (
            current_latest_version.config.code.code_sha256
            if current_latest_version.config.package_type == PackageType.Zip
            else current_latest_version.config.image.code_sha256
        )
        # if the code is a zip package and hot reloaded (hot reloading is currently only supported for zip packagetypes)
        # we cannot enforce the codesha256 check
        is_hot_reloaded_zip_package = (
            current_latest_version.config.package_type == PackageType.Zip
            and current_latest_version.config.code.is_hot_reloading()
        )
        if code_sha256 and current_hash != code_sha256 and not is_hot_reloaded_zip_package:
            raise InvalidParameterValueException(
                f"CodeSHA256 ({code_sha256}) is different from current CodeSHA256 in $LATEST ({current_hash}). Please try again with the CodeSHA256 in $LATEST.",
                Type="User",
            )

        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        changes = {}
        if description is not None:
            changes["description"] = description
        # TODO copy environment instead of restarting one, get rid of all the "Pending"s

        with function.lock:
            if function.next_version > 1 and (
                prev_version := function.versions.get(str(function.next_version - 1))
            ):
                if (
                    prev_version.config.internal_revision
                    == current_latest_version.config.internal_revision
                ):
                    return prev_version, False
            # TODO check if there was a change since last version
            next_version = str(function.next_version)
            function.next_version += 1
            new_id = VersionIdentifier(
                function_name=function_name,
                qualifier=next_version,
                region=region,
                account=account_id,
            )
            apply_on = current_latest_version.config.snap_start["ApplyOn"]
            optimization_status = SnapStartOptimizationStatus.Off
            if apply_on == SnapStartApplyOn.PublishedVersions:
                optimization_status = SnapStartOptimizationStatus.On
            snap_start = SnapStartResponse(
                ApplyOn=apply_on,
                OptimizationStatus=optimization_status,
            )
            new_version = dataclasses.replace(
                current_latest_version,
                config=dataclasses.replace(
                    current_latest_version.config,
                    last_update=None,  # versions never have a last update status
                    state=VersionState(
                        state=State.Pending,
                        code=StateReasonCode.Creating,
                        reason="The function is being created.",
                    ),
                    snap_start=snap_start,
                    **changes,
                ),
                id=new_id,
            )
            function.versions[next_version] = new_version
        return new_version, True

    def _publish_version_from_existing_version(
        self,
        function_name: str,
        region: str,
        account_id: str,
        description: str | None = None,
        revision_id: str | None = None,
        code_sha256: str | None = None,
    ) -> FunctionVersion:
        """
        Publish version from an existing, already initialized LATEST

        :param function_name: Function name
        :param region: region
        :param account_id: account id
        :param description: description
        :param revision_id: revision id (check if current version matches)
        :param code_sha256: code sha (check if current code matches)
        :return: new version
        """
        new_version, changed = self._create_version_model(
            function_name=function_name,
            region=region,
            account_id=account_id,
            description=description,
            revision_id=revision_id,
            code_sha256=code_sha256,
        )
        if not changed:
            return new_version
        self.lambda_service.publish_version(new_version)
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)
        # TODO: re-evaluate data model to prevent this dirty hack just for bumping the revision id
        latest_version = function.versions["$LATEST"]
        function.versions["$LATEST"] = dataclasses.replace(
            latest_version, config=dataclasses.replace(latest_version.config)
        )
        return function.versions.get(new_version.id.qualifier)

    def _publish_version_with_changes(
        self,
        function_name: str,
        region: str,
        account_id: str,
        description: str | None = None,
        revision_id: str | None = None,
        code_sha256: str | None = None,
    ) -> FunctionVersion:
        """
        Publish version together with a new latest version (publish on create / update)

        :param function_name: Function name
        :param region: region
        :param account_id: account id
        :param description: description
        :param revision_id: revision id (check if current version matches)
        :param code_sha256: code sha (check if current code matches)
        :return: new version
        """
        new_version, changed = self._create_version_model(
            function_name=function_name,
            region=region,
            account_id=account_id,
            description=description,
            revision_id=revision_id,
            code_sha256=code_sha256,
        )
        if not changed:
            return new_version
        self.lambda_service.create_function_version(new_version)
        return new_version

    @staticmethod
    def _verify_env_variables(env_vars: dict[str, str]):
        dumped_env_vars = json.dumps(env_vars, separators=(",", ":"))
        if (
            len(dumped_env_vars.encode("utf-8"))
            > config.LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES
        ):
            raise InvalidParameterValueException(
                f"Lambda was unable to configure your environment variables because the environment variables you have provided exceeded the 4KB limit. String measured: {dumped_env_vars}",
                Type="User",
            )

    @staticmethod
    def _validate_snapstart(snap_start: SnapStart, runtime: Runtime):
        apply_on = snap_start.get("ApplyOn")
        if apply_on not in [
            SnapStartApplyOn.PublishedVersions,
            SnapStartApplyOn.None_,
        ]:
            raise ValidationException(
                f"1 validation error detected: Value '{apply_on}' at 'snapStart.applyOn' failed to satisfy constraint: Member must satisfy enum value set: [PublishedVersions, None]"
            )
        if runtime not in SNAP_START_SUPPORTED_RUNTIMES:
            raise InvalidParameterValueException(
                f"{runtime} is not supported for SnapStart enabled functions.", Type="User"
            )

    def _validate_layers(self, new_layers: list[str], region: str, account_id: int):
        if len(new_layers) > LAMBDA_LAYERS_LIMIT_PER_FUNCTION:
            raise InvalidParameterValueException(
                "Cannot reference more than 5 layers.", Type="User"
            )

        visited_layers = dict()
        for layer_version_arn in new_layers:
            layer_region, layer_account_id, layer_name, layer_version = api_utils.parse_layer_arn(
                layer_version_arn
            )
            if layer_version is None:
                raise ValidationException(
                    f"1 validation error detected: Value '[{layer_version_arn}]'"
                    + r" at 'layers' failed to satisfy constraint: Member must satisfy constraint: [Member must have length less than or equal to 140, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: (arn:[a-zA-Z0-9-]+:lambda:[a-zA-Z0-9-]+:\d{12}:layer:[a-zA-Z0-9-_]+:[0-9]+)|(arn:[a-zA-Z0-9-]+:lambda:::awslayer:[a-zA-Z0-9-_]+), Member must not be null]",
                )

            state = lambda_stores[layer_account_id][layer_region]
            layer = state.layers.get(layer_name)
            if layer_account_id == get_aws_account_id():
                if region and layer_region != region:
                    raise InvalidParameterValueException(
                        f"Layers are not in the same region as the function. "
                        f"Layers are expected to be in region {region}.",
                        Type="User",
                    )
                if layer is None or layer.layer_versions.get(layer_version) is None:
                    raise InvalidParameterValueException(
                        f"Layer version {layer_version_arn} does not exist.", Type="User"
                    )
            else:  # External layer from other account
                # TODO: validate IAM layer policy here, allowing access by default for now and only checking region
                if region and layer_region != region:
                    # TODO: detect user or role from context when IAM users are implemented
                    user = "user/localstack-testing"
                    raise AccessDeniedException(
                        f"User: arn:aws:iam::{account_id}:{user} is not authorized to perform: lambda:GetLayerVersion on resource: {layer_version_arn} because no resource-based policy allows the lambda:GetLayerVersion action"
                    )
                if layer is None:
                    # Limitation: cannot fetch external layers when using the same account id as the target layer
                    # because we do not want to trigger the layer fetcher for every non-existing layer.
                    if self.layer_fetcher is None:
                        raise NotImplementedError(
                            "Fetching shared layers from AWS is a pro feature."
                        )

                    layer = self.layer_fetcher.fetch_layer(layer_version_arn)
                    if layer is None:
                        # TODO: detect user or role from context when IAM users are implemented
                        user = "user/localstack-testing"
                        raise AccessDeniedException(
                            f"User: arn:aws:iam::{account_id}:{user} is not authorized to perform: lambda:GetLayerVersion on resource: {layer_version_arn} because no resource-based policy allows the lambda:GetLayerVersion action"
                        )
                    state.layers[layer_name] = layer

            # only the first two matches in the array are considered for the error message
            layer_arn = ":".join(layer_version_arn.split(":")[:-1])
            if layer_arn in visited_layers:
                conflict_layer_version_arn = visited_layers[layer_arn]
                raise InvalidParameterValueException(
                    f"Two different versions of the same layer are not allowed to be referenced in the same function. {conflict_layer_version_arn} and {layer_version_arn} are versions of the same layer.",
                    Type="User",
                )
            visited_layers[layer_arn] = layer_version_arn

    @staticmethod
    def map_layers(new_layers: list[str]) -> list[LayerVersion]:
        layers = []
        for layer_version_arn in new_layers:
            region_name, account_id, layer_name, layer_version = api_utils.parse_layer_arn(
                layer_version_arn
            )
            layer = lambda_stores[account_id][region_name].layers.get(layer_name)
            layer_version = layer.layer_versions.get(layer_version)
            layers.append(layer_version)
        return layers

    @handler(operation="CreateFunction", expand=False)
    def create_function(
        self,
        context: RequestContext,
        request: CreateFunctionRequest,
    ) -> FunctionConfiguration:
        if context.request.content_length > config.LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE:
            raise RequestEntityTooLargeException(
                f"Request must be smaller than {config.LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE} bytes for the CreateFunction operation"
            )

        architectures = request.get("Architectures")
        if architectures:
            if len(architectures) != 1:
                raise ValidationException(
                    f"1 validation error detected: Value '[{', '.join(architectures)}]' at 'architectures' failed to "
                    f"satisfy constraint: Member must have length less than or equal to 1",
                )
            if architectures[0] not in ARCHITECTURES:
                raise ValidationException(
                    f"1 validation error detected: Value '[{', '.join(architectures)}]' at 'architectures' failed to "
                    f"satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
                    f"[x86_64, arm64], Member must not be null]",
                )

        if env_vars := request.get("Environment", {}).get("Variables"):
            self._verify_env_variables(env_vars)

        if layers := request.get("Layers", []):
            self._validate_layers(layers, region=context.region, account_id=context.account_id)

        if not api_utils.is_role_arn(request.get("Role")):
            raise ValidationException(
                f"1 validation error detected: Value '{request.get('Role')}'"
                + " at 'role' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*)?:iam::\\d{12}:role/?[a-zA-Z_0-9+=,.@\\-_/]+"
            )
        if not self.lambda_service.can_assume_role(request.get("Role")):
            raise InvalidParameterValueException(
                "The role defined for the function cannot be assumed by Lambda.", Type="User"
            )
        package_type = request.get("PackageType", PackageType.Zip)
        runtime = request.get("Runtime")
        if package_type == PackageType.Zip and runtime not in IMAGE_MAPPING:
            raise InvalidParameterValueException(
                f"Value {request.get('Runtime')} at 'runtime' failed to satisfy constraint: Member must satisfy enum value set: [java17, provided, nodejs16.x, nodejs14.x, ruby2.7, python3.10, java11, python3.11, dotnet6, go1.x, nodejs18.x, provided.al2, java8, java8.al2, ruby3.2, python3.7, python3.8, python3.9] or be a valid ARN",
                Type="User",
            )
        if snap_start := request.get("SnapStart"):
            self._validate_snapstart(snap_start, runtime)
        state = lambda_stores[context.account_id][context.region]

        function_name = request["FunctionName"]
        with self.create_fn_lock:
            if function_name in state.functions:
                raise ResourceConflictException(f"Function already exist: {function_name}")
            fn = Function(function_name=function_name)
            arn = VersionIdentifier(
                function_name=function_name,
                qualifier="$LATEST",
                region=context.region,
                account=context.account_id,
            )
            # save function code to s3
            code = None
            image = None
            image_config = None
            runtime_version_config = RuntimeVersionConfig(
                # Limitation: the runtime id (presumably sha256 of image) is currently hardcoded
                # Potential implementation: provide (cached) sha256 hash of used Docker image
                RuntimeVersionArn=f"arn:aws:lambda:{context.region}::runtime:8eeff65f6809a3ce81507fe733fe09b835899b99481ba22fd75b5a7338290ec1"
            )
            request_code = request.get("Code")
            if package_type == PackageType.Zip:
                # TODO verify if correct combination of code is set
                if zip_file := request_code.get("ZipFile"):
                    code = store_lambda_archive(
                        archive_file=zip_file,
                        function_name=function_name,
                        region_name=context.region,
                        account_id=context.account_id,
                    )
                elif s3_bucket := request_code.get("S3Bucket"):
                    s3_key = request_code["S3Key"]
                    s3_object_version = request_code.get("S3ObjectVersion")
                    code = store_s3_bucket_archive(
                        archive_bucket=s3_bucket,
                        archive_key=s3_key,
                        archive_version=s3_object_version,
                        function_name=function_name,
                        region_name=context.region,
                        account_id=context.account_id,
                    )
                else:
                    raise LambdaServiceException("Gotta have s3 bucket or zip file")
            elif package_type == PackageType.Image:
                image = request_code.get("ImageUri")
                if not image:
                    raise LambdaServiceException("Gotta have an image when package type is image")
                image = create_image_code(image_uri=image)

                image_config_req = request.get("ImageConfig", {})
                image_config = ImageConfig(
                    command=image_config_req.get("Command"),
                    entrypoint=image_config_req.get("EntryPoint"),
                    working_directory=image_config_req.get("WorkingDirectory"),
                )
                # Runtime management controls are not available when providing a custom image
                runtime_version_config = None

            version = FunctionVersion(
                id=arn,
                config=VersionFunctionConfiguration(
                    last_modified=api_utils.format_lambda_date(datetime.datetime.now()),
                    description=request.get("Description", ""),
                    role=request["Role"],
                    timeout=request.get("Timeout", LAMBDA_DEFAULT_TIMEOUT),
                    runtime=request.get("Runtime"),
                    memory_size=request.get("MemorySize", LAMBDA_DEFAULT_MEMORY_SIZE),
                    handler=request.get("Handler"),
                    package_type=package_type,
                    environment=env_vars,
                    architectures=request.get("Architectures") or [Architecture.x86_64],
                    tracing_config_mode=request.get("TracingConfig", {}).get(
                        "Mode", TracingMode.PassThrough
                    ),
                    image=image,
                    image_config=image_config,
                    code=code,
                    layers=self.map_layers(layers),
                    internal_revision=short_uid(),
                    ephemeral_storage=LambdaEphemeralStorage(
                        size=request.get("EphemeralStorage", {}).get("Size", 512)
                    ),
                    snap_start=SnapStartResponse(
                        ApplyOn=request.get("SnapStart", {}).get("ApplyOn", SnapStartApplyOn.None_),
                        OptimizationStatus=SnapStartOptimizationStatus.Off,
                    ),
                    runtime_version_config=runtime_version_config,
                    dead_letter_arn=request.get("DeadLetterConfig", {}).get("TargetArn"),
                    vpc_config=self._build_vpc_config(request.get("VpcConfig")),
                    state=VersionState(
                        state=State.Pending,
                        code=StateReasonCode.Creating,
                        reason="The function is being created.",
                    ),
                ),
            )
            fn.versions["$LATEST"] = version
            if request.get("Tags"):
                self._store_tags(fn, request["Tags"])
                # TODO: should validation failures here "fail" the function creation like it is now?
            state.functions[function_name] = fn
        self.lambda_service.create_function_version(version)

        if request.get("Publish"):
            version = self._publish_version_with_changes(
                function_name=function_name, region=context.region, account_id=context.account_id
            )

        if config.LAMBDA_SYNCHRONOUS_CREATE:
            # block via retrying until "terminal" condition reached before returning
            if not poll_condition(
                lambda: self._get_function_version(
                    function_name, version.id.qualifier, version.id.account, version.id.region
                ).config.state.state
                in [State.Active, State.Failed],
                timeout=10,
            ):
                LOG.warning(
                    "LAMBDA_SYNCHRONOUS_CREATE is active, but waiting for %s reached timeout.",
                    function_name,
                )

        return api_utils.map_config_out(
            version, return_qualified_arn=False, return_update_status=False
        )

    @handler(operation="UpdateFunctionConfiguration", expand=False)
    def update_function_configuration(
        self, context: RequestContext, request: UpdateFunctionConfigurationRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        function_name = request.get("FunctionName")  # TODO: can this be an ARN too?
        state = lambda_stores[context.account_id][context.region]

        if function_name not in state.functions:
            raise ResourceNotFoundException(
                f"Function not found: {api_utils.unqualified_lambda_arn(function_name=function_name, region=context.region, account=context.account_id)}",
                Type="User",
            )
        function = state.functions[function_name]

        # TODO: lock modification of latest version
        # TODO: notify service for changes relevant to re-provisioning of $LATEST
        latest_version = function.latest()
        latest_version_config = latest_version.config

        revision_id = request.get("RevisionId")
        if revision_id and revision_id != latest_version.config.revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )

        replace_kwargs = {}
        if "EphemeralStorage" in request:
            replace_kwargs["ephemeral_storage"] = LambdaEphemeralStorage(
                request.get("EphemeralStorage", {}).get("Size", 512)
            )  # TODO: do defaults here apply as well?

        if "Role" in request:
            if not api_utils.is_role_arn(request["Role"]):
                raise ValidationException(
                    f"1 validation error detected: Value '{request.get('Role')}'"
                    + " at 'role' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*)?:iam::\\d{12}:role/?[a-zA-Z_0-9+=,.@\\-_/]+"
                )
            replace_kwargs["role"] = request["Role"]

        if "Description" in request:
            replace_kwargs["description"] = request["Description"]

        if "Timeout" in request:
            replace_kwargs["timeout"] = request["Timeout"]

        if "MemorySize" in request:
            replace_kwargs["memory_size"] = request["MemorySize"]

        if "DeadLetterConfig" in request:
            replace_kwargs["dead_letter_arn"] = request.get("DeadLetterConfig", {}).get("TargetArn")

        if vpc_config := request.get("VpcConfig"):
            replace_kwargs["vpc_config"] = self._build_vpc_config(vpc_config)

        if "Runtime" in request:
            if request["Runtime"] not in IMAGE_MAPPING:
                raise InvalidParameterValueException(
                    f"Value {request.get('Runtime')} at 'runtime' failed to satisfy constraint: Member must satisfy enum value set: [java17, provided, nodejs16.x, nodejs14.x, ruby2.7, python3.10, java11, python3.11, dotnet6, go1.x, nodejs18.x, provided.al2, java8, java8.al2, ruby3.2, python3.7, python3.8, python3.9] or be a valid ARN",
                    Type="User",
                )
            replace_kwargs["runtime"] = request["Runtime"]

        if snap_start := request.get("SnapStart"):
            runtime = replace_kwargs.get("runtime") or latest_version_config.runtime
            self._validate_snapstart(snap_start, runtime)
            replace_kwargs["snap_start"] = SnapStartResponse(
                ApplyOn=snap_start.get("ApplyOn", SnapStartApplyOn.None_),
                OptimizationStatus=SnapStartOptimizationStatus.Off,
            )

        if "Environment" in request:
            if env_vars := request.get("Environment", {}).get("Variables", {}):
                self._verify_env_variables(env_vars)
            replace_kwargs["environment"] = env_vars

        if "Layers" in request:
            new_layers = request["Layers"]
            if new_layers:
                self._validate_layers(
                    new_layers, region=context.region, account_id=context.account_id
                )
            replace_kwargs["layers"] = self.map_layers(new_layers)

        if "ImageConfig" in request:
            new_image_config = request["ImageConfig"]
            replace_kwargs["image_config"] = ImageConfig(
                command=new_image_config.get("Command"),
                entrypoint=new_image_config.get("EntryPoint"),
                working_directory=new_image_config.get("WorkingDirectory"),
            )

        if "TracingConfig" in request:
            new_mode = request.get("TracingConfig", {}).get("Mode")
            if new_mode:
                replace_kwargs["tracing_config_mode"] = new_mode

        new_latest_version = dataclasses.replace(
            latest_version,
            config=dataclasses.replace(
                latest_version_config,
                last_modified=api_utils.generate_lambda_date(),
                internal_revision=short_uid(),
                last_update=UpdateStatus(
                    status=LastUpdateStatus.InProgress,
                    code="Creating",
                    reason="The function is being created.",
                ),
                **replace_kwargs,
            ),
        )
        function.versions["$LATEST"] = new_latest_version  # TODO: notify
        self.lambda_service.update_version(new_version=new_latest_version)

        return api_utils.map_config_out(new_latest_version)

    @handler(operation="UpdateFunctionCode", expand=False)
    def update_function_code(
        self, context: RequestContext, request: UpdateFunctionCodeRequest
    ) -> FunctionConfiguration:
        """updates the $LATEST version of the function"""
        # only supports normal zip packaging atm
        # if request.get("Publish"):
        #     self.lambda_service.create_function_version()

        function_name = request.get("FunctionName")
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(function_name, None, context)

        store = lambda_stores[account_id][region]
        if function_name not in store.functions:
            raise ResourceNotFoundException(
                f"Function not found: {api_utils.unqualified_lambda_arn(function_name=function_name, region=region, account=account_id)}",
                Type="User",
            )
        function = store.functions[function_name]

        revision_id = request.get("RevisionId")
        if revision_id and revision_id != function.latest().config.revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )

        # TODO verify if correct combination of code is set
        image = None
        if (
            request.get("ZipFile") or request.get("S3Bucket")
        ) and function.latest().config.package_type == PackageType.Image:
            raise InvalidParameterValueException(
                "Please provide ImageUri when updating a function with packageType Image.",
                Type="User",
            )
        elif request.get("ImageUri") and function.latest().config.package_type == PackageType.Zip:
            raise InvalidParameterValueException(
                "Please don't provide ImageUri when updating a function with packageType Zip.",
                Type="User",
            )

        if zip_file := request.get("ZipFile"):
            code = store_lambda_archive(
                archive_file=zip_file,
                function_name=function_name,
                region_name=region,
                account_id=account_id,
            )
        elif s3_bucket := request.get("S3Bucket"):
            s3_key = request["S3Key"]
            s3_object_version = request.get("S3ObjectVersion")
            code = store_s3_bucket_archive(
                archive_bucket=s3_bucket,
                archive_key=s3_key,
                archive_version=s3_object_version,
                function_name=function_name,
                region_name=region,
                account_id=account_id,
            )
        elif image := request.get("ImageUri"):
            code = None
            image = create_image_code(image_uri=image)
        else:
            raise LambdaServiceException("Gotta have s3 bucket or zip file or image")

        old_function_version = function.versions.get("$LATEST")
        replace_kwargs = {"code": code} if code else {"image": image}
        config = dataclasses.replace(
            old_function_version.config,
            internal_revision=short_uid(),
            last_modified=api_utils.generate_lambda_date(),
            last_update=UpdateStatus(
                status=LastUpdateStatus.InProgress,
                code="Creating",
                reason="The function is being created.",
            ),
            **replace_kwargs,
        )
        function_version = dataclasses.replace(old_function_version, config=config)
        function.versions["$LATEST"] = function_version

        self.lambda_service.update_version(new_version=function_version)
        if request.get("Publish"):
            function_version = self._publish_version_with_changes(
                function_name=function_name, region=region, account_id=account_id
            )
        return api_utils.map_config_out(
            function_version, return_qualified_arn=bool(request.get("Publish"))
        )

    # TODO: does deleting the latest published version affect the next versions number?
    # TODO: what happens when we call this with a qualifier and a fully qualified ARN? (+ conflicts?)
    # TODO: test different ARN patterns (shorthand ARN?)
    # TODO: test deleting across regions?
    # TODO: test mismatch between context region and region in ARN
    # TODO: test qualifier $LATEST, alias-name and version
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        store = lambda_stores[account_id][region]
        if qualifier == "$LATEST":
            raise InvalidParameterValueException(
                "$LATEST version cannot be deleted without deleting the function.", Type="User"
            )

        if function_name not in store.functions:
            e = ResourceNotFoundException(
                f"Function not found: {api_utils.unqualified_lambda_arn(function_name=function_name, region=region, account=account_id)}",
                Type="User",
            )
            raise e
        function = store.functions.get(function_name)

        if qualifier:
            # delete a version of the function
            version = function.versions.pop(qualifier, None)
            if version:
                self.lambda_service.stop_version(version.qualified_arn())
                destroy_code_if_not_used(code=version.config.code, function=function)
        else:
            # delete the whole function
            function = store.functions.pop(function_name)
            for version in function.versions.values():
                self.lambda_service.stop_version(qualified_arn=version.id.qualified_arn())
                # we can safely destroy the code here
                if version.config.code:
                    version.config.code.destroy()

    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,  # (only relevant for lambda@edge)
        function_version: FunctionVersionApi = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsResponse:
        state = lambda_stores[context.account_id][context.region]

        if function_version and function_version != FunctionVersionApi.ALL:
            raise ValidationException(
                f"1 validation error detected: Value '{function_version}'"
                + " at 'functionVersion' failed to satisfy constraint: Member must satisfy enum value set: [ALL]"
            )

        if function_version == FunctionVersionApi.ALL:
            # include all versions for all function
            versions = [v for f in state.functions.values() for v in f.versions.values()]
            return_qualified_arn = True
        else:
            versions = [f.latest() for f in state.functions.values()]
            return_qualified_arn = False

        versions = [
            api_utils.map_to_list_response(
                api_utils.map_config_out(fc, return_qualified_arn=return_qualified_arn)
            )
            for fc in versions
        ]
        versions = PaginatedList(versions)
        page, token = versions.get_page(
            lambda version: version["FunctionArn"],
            marker,
            max_items,
        )
        return ListFunctionsResponse(Functions=page, NextMarker=token)

    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetFunctionResponse:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        fn = lambda_stores[account_id][region].functions.get(function_name)
        if fn is None:
            if qualifier is None:
                raise ResourceNotFoundException(
                    f"Function not found: {api_utils.unqualified_lambda_arn(function_name, account_id, region)}",
                    Type="User",
                )
            else:
                raise ResourceNotFoundException(
                    f"Function not found: {api_utils.qualified_lambda_arn(function_name, qualifier, account_id, region)}",
                    Type="User",
                )
        alias_name = None
        if qualifier and api_utils.qualifier_is_alias(qualifier):
            if qualifier not in fn.aliases:
                alias_arn = api_utils.qualified_lambda_arn(
                    function_name, qualifier, account_id, region
                )
                raise ResourceNotFoundException(f"Function not found: {alias_arn}", Type="User")
            alias_name = qualifier
            qualifier = fn.aliases[alias_name].function_version

        version = self._get_function_version(
            function_name=function_name,
            qualifier=qualifier,
            account_id=account_id,
            region=region,
        )
        tags = self._get_tags(fn)
        additional_fields = {}
        if tags:
            additional_fields["Tags"] = tags
        code_location = None
        if code := version.config.code:
            code_location = FunctionCodeLocation(
                Location=code.generate_presigned_url(), RepositoryType="S3"
            )
        elif image := version.config.image:
            code_location = FunctionCodeLocation(
                ImageUri=image.image_uri,
                RepositoryType=image.repository_type,
                ResolvedImageUri=image.resolved_image_uri,
            )

        return GetFunctionResponse(
            Configuration=api_utils.map_config_out(
                version, return_qualified_arn=bool(qualifier), alias_name=alias_name
            ),
            Code=code_location,  # TODO
            **additional_fields
            # Concurrency={},  # TODO
        )

    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> FunctionConfiguration:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        # CAVE: THIS RETURN VALUE IS *NOT* THE SAME AS IN get_function (!) but seems to be only configuration part?
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        version = self._get_function_version(
            function_name=function_name,
            qualifier=qualifier,
            account_id=account_id,
            region=region,
        )
        return api_utils.map_config_out(version, return_qualified_arn=bool(qualifier))

    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType = None,
        log_type: LogType = None,
        client_context: String = None,
        payload: IO[Blob] = None,
        qualifier: Qualifier = None,
    ) -> InvocationResponse:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        try:
            self._get_function(function_name=function_name, account_id=account_id, region=region)
        except ResourceNotFoundException:
            # remove this block when AWS updates the stepfunctions image to support aws-sdk invocations
            if "localstack-internal-awssdk" in function_name:
                # init aws-sdk stepfunctions task handler
                from localstack.services.stepfunctions.packages import stepfunctions_local_package

                code = load_file(
                    os.path.join(
                        stepfunctions_local_package.get_installed_dir(),
                        "localstack-internal-awssdk",
                        "awssdk.zip",
                    ),
                    mode="rb",
                )
                lambda_client = connect_to().lambda_
                lambda_client.create_function(
                    FunctionName="localstack-internal-awssdk",
                    Runtime=Runtime.nodejs16_x,
                    Handler="index.handler",
                    Code={"ZipFile": code},
                    Role="arn:aws:iam::{account_id}:role/lambda-test-role".format(
                        account_id=account_id
                    ),  # TODO: proper role
                )

        time_before = time.perf_counter()
        try:
            invocation_result = self.lambda_service.invoke(
                function_name=function_name,
                qualifier=qualifier,
                region=region,
                account_id=account_id,
                invocation_type=invocation_type,
                client_context=client_context,
                request_id=context.request_id,
                payload=payload.read() if payload else None,
            )
        except ServiceException:
            raise
        except EnvironmentStartupTimeoutException as e:
            raise LambdaServiceException("Internal error while executing lambda") from e
        except Exception as e:
            LOG.error("Error while invoking lambda", exc_info=e)
            raise LambdaServiceException("Internal error while executing lambda") from e

        if invocation_type == InvocationType.Event:
            # This happens when invocation type is event
            return InvocationResponse(StatusCode=202)
        if invocation_type == InvocationType.DryRun:
            # This happens when invocation type is dryrun
            return InvocationResponse(StatusCode=204)
        LOG.debug("Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000)

        response = InvocationResponse(
            StatusCode=200,
            Payload=invocation_result.payload,
            ExecutedVersion=invocation_result.executed_version,
        )

        if invocation_result.is_error:
            response["FunctionError"] = "Unhandled"

        if log_type == LogType.Tail:
            response["LogResult"] = to_str(
                base64.b64encode(to_bytes(invocation_result.logs)[-4096:])
            )

        return response

    # Version operations
    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String = None,
        description: Description = None,
        revision_id: String = None,
    ) -> FunctionConfiguration:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        new_version = self._publish_version_from_existing_version(
            function_name=function_name,
            description=description,
            account_id=account_id,
            region=region,
            revision_id=revision_id,
            code_sha256=code_sha256,
        )
        return api_utils.map_config_out(new_version, return_qualified_arn=True)

    def list_versions_by_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListVersionsByFunctionResponse:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        versions = [
            api_utils.map_to_list_response(
                api_utils.map_config_out(version=version, return_qualified_arn=True)
            )
            for version in function.versions.values()
        ]
        items = PaginatedList(versions)
        page, token = items.get_page(
            lambda item: item,
            marker,
            max_items,
        )
        return ListVersionsByFunctionResponse(Versions=page, NextMarker=token)

    # Alias

    def _create_routing_config_model(
        self, routing_config_dict: dict[str, float], function_version: FunctionVersion
    ):
        if len(routing_config_dict) > 1:
            raise InvalidParameterValueException(
                "Number of items in AdditionalVersionWeights cannot be greater than 1",
                Type="User",
            )
        # should be exactly one item here, still iterating, might be supported in the future
        for key, value in routing_config_dict.items():
            if value < 0.0 or value >= 1.0:
                raise ValidationException(
                    f"1 validation error detected: Value '{{{key}={value}}}' at 'routingConfig.additionalVersionWeights' failed to satisfy constraint: Map value must satisfy constraint: [Member must have value less than or equal to 1.0, Member must have value greater than or equal to 0.0, Member must not be null]"
                )
            if key == function_version.id.qualifier:
                raise InvalidParameterValueException(
                    f"Invalid function version {function_version.id.qualifier}. Function version {function_version.id.qualifier} is already included in routing configuration.",
                    Type="User",
                )
            # check if version target is latest, then no routing config is allowed
            if function_version.id.qualifier == "$LATEST":
                raise InvalidParameterValueException(
                    "$LATEST is not supported for an alias pointing to more than 1 version"
                )
            if not api_utils.qualifier_is_version(key):
                raise ValidationException(
                    f"1 validation error detected: Value '{{{key}={value}}}' at 'routingConfig.additionalVersionWeights' failed to satisfy constraint: Map keys must satisfy constraint: [Member must have length less than or equal to 1024, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: [0-9]+, Member must not be null]"
                )

            # checking if the version in the config exists
            self._get_function_version(
                function_name=function_version.id.function_name,
                qualifier=key,
                region=function_version.id.region,
                account_id=function_version.id.account,
            )
        return AliasRoutingConfig(version_weights=routing_config_dict)

    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        target_version = self._get_function_version(
            function_name=function_name,
            qualifier=function_version,
            region=region,
            account_id=account_id,
        )
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        # description is always present, if not specified it's an empty string
        description = description or ""
        with function.lock:
            if existing_alias := function.aliases.get(name):
                raise ResourceConflictException(
                    f"Alias already exists: {api_utils.map_alias_out(alias=existing_alias, function=function)['AliasArn']}",
                    Type="User",
                )
            # checking if the version exists
            routing_configuration = None
            if routing_config and (
                routing_config_dict := routing_config.get("AdditionalVersionWeights")
            ):
                routing_configuration = self._create_routing_config_model(
                    routing_config_dict, target_version
                )

            alias = VersionAlias(
                name=name,
                function_version=function_version,
                description=description,
                routing_configuration=routing_configuration,
            )
            function.aliases[name] = alias
        return api_utils.map_alias_out(alias=alias, function=function)

    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListAliasesResponse:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        aliases = [
            api_utils.map_alias_out(alias, function)
            for alias in function.aliases.values()
            if function_version is None or alias.function_version == function_version
        ]

        aliases = PaginatedList(aliases)
        page, token = aliases.get_page(
            lambda alias: alias["AliasArn"],
            marker,
            max_items,
        )

        return ListAliasesResponse(Aliases=page, NextMarker=token)

    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        if name not in function.aliases:
            raise ValueError("Alias not found")  # TODO proper exception
        function.aliases.pop(name, None)

        # cleanup related resources
        if name in function.provisioned_concurrency_configs:
            function.provisioned_concurrency_configs.pop(name)

    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        if not (alias := function.aliases.get(name)):
            raise ResourceNotFoundException(
                f"Cannot find alias arn: {api_utils.qualified_lambda_arn(function_name=function_name, qualifier=name, region=region, account=account_id)}",
                Type="User",
            )
        return api_utils.map_alias_out(alias=alias, function=function)

    def update_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version = None,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
        revision_id: String = None,
    ) -> AliasConfiguration:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name = api_utils.get_function_name(function_name, context)
        function = self._get_function(
            function_name=function_name, region=region, account_id=account_id
        )
        if not (alias := function.aliases.get(name)):
            raise ValueError("Alias not found")  # TODO proper exception
        if revision_id and alias.revision_id != revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )
        changes = {}
        if function_version is not None:
            changes |= {"function_version": function_version}
        if description is not None:
            changes |= {"description": description}
        if routing_config is not None:
            # if it is an empty dict or AdditionalVersionWeights is empty, set routing config to None
            new_routing_config = None
            if routing_config_dict := routing_config.get("AdditionalVersionWeights"):
                new_routing_config = self._create_routing_config_model(routing_config_dict)
            changes |= {"routing_configuration": new_routing_config}
        # even if no changes are done, we have to update revision id for some reason
        old_alias = alias
        alias = dataclasses.replace(alias, **changes)
        function.aliases[name] = alias

        # TODO: signal lambda service that pointer potentially changed
        self.lambda_service.update_alias(old_alias=old_alias, new_alias=alias, function=function)

        return api_utils.map_alias_out(alias=alias, function=function)

    # =======================================
    # ======= EVENT SOURCE MAPPINGS =========
    # =======================================

    @handler("CreateEventSourceMapping", expand=False)
    def create_event_source_mapping(
        self,
        context: RequestContext,
        request: CreateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:
        if "EventSourceArn" not in request:
            raise InvalidParameterValueException("Unrecognized event source.", Type="User")

        service = extract_service_from_arn(request.get("EventSourceArn"))
        if service in ["dynamodb", "kinesis", "kafka"] and "StartingPosition" not in request:
            raise InvalidParameterValueException(
                "1 validation error detected: Value null at 'startingPosition' failed to satisfy constraint: Member must not be null.",
                Type="User",
            )

        state = lambda_stores[context.account_id][context.region]
        function_name = request["FunctionName"]

        if api_utils.FULL_FN_ARN_PATTERN.match(function_name):
            fn_arn = function_name
            function_name = api_utils.get_function_name(function_name, context)
        else:
            fn_arn = api_utils.unqualified_lambda_arn(
                function_name, context.account_id, context.region
            )

        fn = state.functions.get(function_name)
        if not fn:
            raise InvalidParameterValueException("Function does not exist", Type="User")

        # TODO: check if alias/version exists

        new_uuid = long_uid()

        # defaults etc. vary depending on type of event source
        # TODO: find a better abstraction to create these
        params = request.copy()
        params.pop("FunctionName")
        batch_size = api_utils.validate_and_set_batch_size(
            request["EventSourceArn"], request.get("BatchSize")
        )
        params["FunctionArn"] = fn_arn
        params["BatchSize"] = batch_size
        params["UUID"] = new_uuid
        params["MaximumBatchingWindowInSeconds"] = request.get("MaximumBatchingWindowInSeconds", 0)
        params["LastModified"] = api_utils.generate_lambda_date()
        params["FunctionResponseTypes"] = request.get("FunctionResponseTypes", [])
        params["State"] = "Enabled"

        if "sqs" in request["EventSourceArn"]:
            params["StateTransitionReason"] = "USER_INITIATED"
            if batch_size > 10 and request.get("MaximumBatchingWindowInSeconds", 0) == 0:
                raise InvalidParameterValueException(
                    "Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10",
                    Type="User",
                )
        else:
            # afaik every other one currently is a stream
            params["StateTransitionReason"] = "User action"
            params["MaximumRetryAttempts"] = request.get("MaximumRetryAttempts", -1)
            params["ParallelizationFactor"] = request.get("ParallelizationFactor", 1)
            params["BisectBatchOnFunctionError"] = request.get("BisectBatchOnFunctionError", False)
            params["LastProcessingResult"] = "No records processed"
            params["MaximumRecordAgeInSeconds"] = request.get("MaximumRecordAgeInSeconds", -1)
            params["TumblingWindowInSeconds"] = request.get("TumblingWindowInSeconds", 0)
            destination_config = request.get("DestinationConfig", {"OnFailure": {}})
            self._validate_destination_config(state, function_name, destination_config)
            params["DestinationConfig"] = destination_config

        # TODO: create domain models and map accordingly

        esm_config = EventSourceMappingConfiguration(**params)
        filter_criteria = esm_config.get("FilterCriteria")
        if filter_criteria:
            # validate for valid json
            if not validate_filters(filter_criteria):
                raise InvalidParameterValueException(
                    "Invalid filter pattern definition.", Type="User"
                )  # TODO: verify

        state.event_source_mappings[new_uuid] = esm_config

        # TODO: evaluate after temp migration
        EventSourceListener.start_listeners_for_asf(request, self.lambda_service)

        return {**esm_config, "State": "Creating"}  # TODO: should be set asynchronously

    @handler("UpdateEventSourceMapping", expand=False)
    def update_event_source_mapping(
        self,
        context: RequestContext,
        request: UpdateEventSourceMappingRequest,
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        request_data = {**request}
        uuid = request_data.pop("UUID", None)
        if not uuid:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        old_event_source_mapping = state.event_source_mappings.get(uuid)
        if old_event_source_mapping is None:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )  # TODO: test?
        event_source_mapping = {**old_event_source_mapping, **request_data}

        temp_params = (
            {}
        )  # values only set for the returned response, not saved internally (e.g. transient state)

        if request.get("Enabled") is not None:
            if request["Enabled"]:
                esm_state = "Enabled"
            else:
                esm_state = "Disabled"
                temp_params["State"] = "Disabling"  # TODO: make this properly async
            event_source_mapping["State"] = esm_state

        if request.get("BatchSize"):
            batch_size = api_utils.validate_and_set_batch_size(
                event_source_mapping["EventSourceArn"], request["BatchSize"]
            )
            if batch_size > 10 and request.get("MaximumBatchingWindowInSeconds", 0) == 0:
                raise InvalidParameterValueException(
                    "Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10",
                    Type="User",
                )
        if request.get("DestinationConfig"):
            destination_config = request["DestinationConfig"]
            self._validate_destination_config(
                state, event_source_mapping["FunctionName"], destination_config
            )
            event_source_mapping["DestinationConfig"] = destination_config
        event_source_mapping["LastProcessingResult"] = "OK"
        state.event_source_mappings[uuid] = event_source_mapping
        return {**event_source_mapping, **temp_params}

    def delete_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        event_source_mapping = state.event_source_mappings.get(uuid)
        if not event_source_mapping:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        esm = state.event_source_mappings.pop(uuid)
        return {**esm, "State": "Deleting"}

    def get_event_source_mapping(
        self, context: RequestContext, uuid: String
    ) -> EventSourceMappingConfiguration:
        state = lambda_stores[context.account_id][context.region]
        event_source_mapping = state.event_source_mappings.get(uuid)
        if not event_source_mapping:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        return event_source_mapping

    def list_event_source_mappings(
        self,
        context: RequestContext,
        event_source_arn: Arn = None,
        function_name: FunctionName = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListEventSourceMappingsResponse:
        state = lambda_stores[context.account_id][context.region]

        esms = state.event_source_mappings.values()

        if event_source_arn:  # TODO: validate pattern
            esms = [e for e in esms if e["EventSourceArn"] == event_source_arn]

        if function_name:
            esms = [e for e in esms if function_name in e["FunctionArn"]]

        esms = PaginatedList(esms)
        page, token = esms.get_page(
            lambda x: x["UUID"],
            marker,
            max_items,
        )
        return ListEventSourceMappingsResponse(EventSourceMappings=page, NextMarker=token)

    # =======================================
    # ============ FUNCTION URLS ============
    # =======================================

    # TODO: what happens if function state is not active?
    def create_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        auth_type: FunctionUrlAuthType,
        qualifier: FunctionUrlQualifier = None,
        cors: Cors = None,
        invoke_mode: InvokeMode = None,
    ) -> CreateFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        if qualifier == "$LATEST":
            raise ValidationException(
                "1 validation error detected: Value '$LATEST' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: ((?!^\\d+$)^[0-9a-zA-Z-_]+$)"
            )
        if qualifier and api_utils.qualifier_is_version(qualifier):
            raise ValidationException(
                f"1 validation error detected: Value '{qualifier}' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (^\\$LATEST$)|((?!^[0-9]+$)([a-zA-Z0-9-_]+))"
            )
        fn = state.functions.get(function_name)
        if fn is None:
            raise ResourceNotFoundException("Function does not exist", Type="User")

        url_config = fn.function_url_configs.get(qualifier or "$LATEST")
        if url_config:
            raise ResourceConflictException(
                f"Failed to create function url config for [functionArn = {url_config.function_arn}]. Error message:  FunctionUrlConfig exists for this Lambda function",
                Type="User",
            )

        if qualifier and qualifier != "$LATEST" and qualifier not in fn.aliases:
            raise ResourceNotFoundException("Function does not exist", Type="User")

        normalized_qualifier = qualifier or "$LATEST"

        function_arn = (
            api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )
            if qualifier
            else api_utils.unqualified_lambda_arn(function_name, context.account_id, context.region)
        )

        # create function URL config
        url_id = api_utils.generate_random_url_id()

        host_definition = localstack_host(
            use_localhost_cloud=True, custom_port=config.EDGE_PORT_HTTP or config.EDGE_PORT
        )
        fn.function_url_configs[normalized_qualifier] = FunctionUrlConfig(
            function_arn=function_arn,
            function_name=function_name,
            cors=cors,
            url_id=url_id,
            url=f"http://{url_id}.lambda-url.{context.region}.{host_definition.host_and_port()}/",  # TODO: https support
            auth_type=auth_type,
            creation_time=api_utils.generate_lambda_date(),
            last_modified_time=api_utils.generate_lambda_date(),
        )

        # persist and start URL
        # TODO: implement URL invoke
        api_url_config = api_utils.map_function_url_config(
            fn.function_url_configs[normalized_qualifier]
        )

        return CreateFunctionUrlConfigResponse(
            FunctionUrl=api_url_config["FunctionUrl"],
            FunctionArn=api_url_config["FunctionArn"],
            AuthType=api_url_config["AuthType"],
            Cors=api_url_config["Cors"],
            CreationTime=api_url_config["CreationTime"],
        )

    def get_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> GetFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        fn_name, qualifier = api_utils.get_name_and_qualifier(function_name, qualifier, context)

        if qualifier == "$LATEST":
            raise ValidationException(
                "1 validation error detected: Value '$LATEST' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: ((?!^\\d+$)^[0-9a-zA-Z-_]+$)"
            )
        if qualifier and api_utils.qualifier_is_version(qualifier):
            raise ValidationException(
                f"1 validation error detected: Value '{qualifier}' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (^\\$LATEST$)|((?!^[0-9]+$)([a-zA-Z0-9-_]+))"
            )

        resolved_fn = state.functions.get(fn_name)
        if not resolved_fn:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        qualifier = qualifier or "$LATEST"
        url_config = resolved_fn.function_url_configs.get(qualifier)
        if not url_config:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        return api_utils.map_function_url_config(url_config)

    def update_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
        auth_type: FunctionUrlAuthType = None,
        cors: Cors = None,
        invoke_mode: InvokeMode = None,
    ) -> UpdateFunctionUrlConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        if qualifier == "$LATEST":
            raise ValidationException(
                "1 validation error detected: Value '$LATEST' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: ((?!^\\d+$)^[0-9a-zA-Z-_]+$)"
            )
        if qualifier and api_utils.qualifier_is_version(qualifier):
            raise ValidationException(
                f"1 validation error detected: Value '{qualifier}' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (^\\$LATEST$)|((?!^[0-9]+$)([a-zA-Z0-9-_]+))"
            )

        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("Function does not exist", Type="User")

        normalized_qualifier = qualifier or "$LATEST"

        if (
            api_utils.qualifier_is_alias(normalized_qualifier)
            and normalized_qualifier not in fn.aliases
        ):
            raise ResourceNotFoundException("Function does not exist", Type="User")

        url_config = fn.function_url_configs.get(normalized_qualifier)
        if not url_config:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        changes = {
            "last_modified_time": api_utils.generate_lambda_date(),
            **({"cors": cors} if cors is not None else {}),
            **({"auth_type": auth_type} if auth_type is not None else {}),
        }
        new_url_config = dataclasses.replace(url_config, **changes)
        fn.function_url_configs[normalized_qualifier] = new_url_config

        return UpdateFunctionUrlConfigResponse(
            FunctionUrl=new_url_config.url,
            FunctionArn=new_url_config.function_arn,
            AuthType=new_url_config.auth_type,
            Cors=new_url_config.cors,
            CreationTime=new_url_config.creation_time,
            LastModifiedTime=new_url_config.last_modified_time,
        )

    # TODO: does only specifying the function name, also delete the ones from all related aliases?
    def delete_function_url_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: FunctionUrlQualifier = None,
    ) -> None:
        state = lambda_stores[context.account_id][context.region]

        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        if qualifier == "$LATEST":
            raise ValidationException(
                "1 validation error detected: Value '$LATEST' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: ((?!^\\d+$)^[0-9a-zA-Z-_]+$)"
            )
        if qualifier and api_utils.qualifier_is_version(qualifier):
            raise ValidationException(
                f"1 validation error detected: Value '{qualifier}' at 'qualifier' failed to satisfy constraint: Member must satisfy regular expression pattern: (^\\$LATEST$)|((?!^[0-9]+$)([a-zA-Z0-9-_]+))"
            )
        resolved_fn = state.functions.get(function_name)
        if not resolved_fn:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        qualifier = qualifier or "$LATEST"
        url_config = resolved_fn.function_url_configs.get(qualifier)
        if not url_config:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        del resolved_fn.function_url_configs[qualifier]

    def list_function_url_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxItems = None,
    ) -> ListFunctionUrlConfigsResponse:
        state = lambda_stores[context.account_id][context.region]

        fn_name = api_utils.get_function_name(function_name, context)
        resolved_fn = state.functions.get(fn_name)
        if not resolved_fn:
            raise ResourceNotFoundException("Function does not exist", Type="User")

        url_configs = [
            api_utils.map_function_url_config(fn_conf)
            for fn_conf in resolved_fn.function_url_configs.values()
        ]
        url_configs = PaginatedList(url_configs)
        page, token = url_configs.get_page(
            lambda url_config: url_config["FunctionArn"],
            marker,
            max_items,
        )
        url_configs = page
        return ListFunctionUrlConfigsResponse(FunctionUrlConfigs=url_configs, NextMarker=token)

    # =======================================
    # ============  Permissions  ============
    # =======================================

    @handler("AddPermission", expand=False)
    def add_permission(
        self,
        context: RequestContext,
        request: AddPermissionRequest,
    ) -> AddPermissionResponse:
        function_name, qualifier = api_utils.get_name_and_qualifier(
            request.get("FunctionName"), request.get("Qualifier"), context
        )

        # validate qualifier
        if qualifier is not None:
            self._validate_qualifier_expression(qualifier)
            if qualifier == "$LATEST":
                raise InvalidParameterValueException(
                    "We currently do not support adding policies for $LATEST.", Type="User"
                )

        resolved_fn = self._get_function(function_name, context.account_id, context.region)
        resolved_qualifier, fn_arn = self._resolve_fn_qualifier(resolved_fn, qualifier)

        revision_id = request.get("RevisionId")
        if revision_id:
            fn_revision_id = self._function_revision_id(resolved_fn, resolved_qualifier)
            if revision_id != fn_revision_id:
                raise PreconditionFailedException(
                    "The Revision Id provided does not match the latest Revision Id. "
                    "Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                    Type="User",
                )

        request_sid = request["StatementId"]
        if not bool(STATEMENT_ID_REGEX.match(request_sid)):
            raise ValidationException(
                f"1 validation error detected: Value '{request_sid}' at 'statementId' failed to satisfy constraint: Member must satisfy regular expression pattern: ([a-zA-Z0-9-_]+)"
            )
        # check for an already existing policy and any conflicts in existing statements
        existing_policy = resolved_fn.permissions.get(resolved_qualifier)
        if existing_policy:
            if request_sid in [s["Sid"] for s in existing_policy.policy.Statement]:
                # uniqueness scope: statement id needs to be unique per qualified function ($LATEST, version, or alias)
                # Counterexample: the same sid can exist within $LATEST, version, and alias
                raise ResourceConflictException(
                    f"The statement id ({request_sid}) provided already exists. Please provide a new statement id, or remove the existing statement.",
                    Type="User",
                )

        permission_statement = api_utils.build_statement(
            fn_arn,
            request["StatementId"],
            request["Action"],
            request["Principal"],
            source_arn=request.get("SourceArn"),
            source_account=request.get("SourceAccount"),
            principal_org_id=request.get("PrincipalOrgID"),
            event_source_token=request.get("EventSourceToken"),
            auth_type=request.get("FunctionUrlAuthType"),
        )
        new_policy = existing_policy
        if not existing_policy:
            new_policy = FunctionResourcePolicy(
                policy=ResourcePolicy(Version="2012-10-17", Id="default", Statement=[])
            )
        new_policy.policy.Statement.append(permission_statement)
        if not existing_policy:
            resolved_fn.permissions[resolved_qualifier] = new_policy

        # Update revision id of alias or version
        # TODO: re-evaluate data model to prevent this dirty hack just for bumping the revision id
        # TODO: does that need a `with function.lock` for atomic updates of the policy + revision_id?
        if api_utils.qualifier_is_alias(resolved_qualifier):
            resolved_alias = resolved_fn.aliases[resolved_qualifier]
            resolved_fn.aliases[resolved_qualifier] = dataclasses.replace(resolved_alias)
        # Assumes that a non-alias is a version
        else:
            resolved_version = resolved_fn.versions[resolved_qualifier]
            resolved_fn.versions[resolved_qualifier] = dataclasses.replace(
                resolved_version, config=dataclasses.replace(resolved_version.config)
            )
        return AddPermissionResponse(Statement=json.dumps(permission_statement))

    def remove_permission(
        self,
        context: RequestContext,
        function_name: FunctionName,
        statement_id: NamespacedStatementId,
        qualifier: Qualifier = None,
        revision_id: String = None,
    ) -> None:
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        if qualifier is not None:
            self._validate_qualifier_expression(qualifier)

        state = lambda_stores[context.account_id][context.region]
        resolved_fn = state.functions.get(function_name)
        if resolved_fn is None:
            fn_arn = api_utils.unqualified_lambda_arn(
                function_name, context.account_id, context.region
            )
            raise ResourceNotFoundException(f"No policy found for: {fn_arn}", Type="User")

        resolved_qualifier, _ = self._resolve_fn_qualifier(resolved_fn, qualifier)
        function_permission = resolved_fn.permissions.get(resolved_qualifier)
        if not function_permission:
            raise ResourceNotFoundException(
                "No policy is associated with the given resource.", Type="User"
            )

        # try to find statement in policy and delete it
        statement = None
        for s in function_permission.policy.Statement:
            if s["Sid"] == statement_id:
                statement = s
                break

        if not statement:
            raise ResourceNotFoundException(
                f"Statement {statement_id} is not found in resource policy.", Type="User"
            )
        fn_revision_id = self._function_revision_id(resolved_fn, resolved_qualifier)
        if revision_id and revision_id != fn_revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
                Type="User",
            )
        function_permission.policy.Statement.remove(statement)

        # Update revision id for alias or version
        # TODO: re-evaluate data model to prevent this dirty hack just for bumping the revision id
        # TODO: does that need a `with function.lock` for atomic updates of the policy + revision_id?
        if api_utils.qualifier_is_alias(resolved_qualifier):
            resolved_alias = resolved_fn.aliases[resolved_qualifier]
            resolved_fn.aliases[resolved_qualifier] = dataclasses.replace(resolved_alias)
        # Assumes that a non-alias is a version
        else:
            resolved_version = resolved_fn.versions[resolved_qualifier]
            resolved_fn.versions[resolved_qualifier] = dataclasses.replace(
                resolved_version, config=dataclasses.replace(resolved_version.config)
            )

        # remove the policy as a whole when there's no statement left in it
        if len(function_permission.policy.Statement) == 0:
            del resolved_fn.permissions[resolved_qualifier]

    def get_policy(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,
    ) -> GetPolicyResponse:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )

        if qualifier is not None:
            self._validate_qualifier_expression(qualifier)

        resolved_fn = self._get_function(function_name, account_id, region)

        resolved_qualifier = qualifier or "$LATEST"
        function_permission = resolved_fn.permissions.get(resolved_qualifier)
        if not function_permission:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        fn_revision_id = None
        if api_utils.qualifier_is_alias(resolved_qualifier):
            resolved_alias = resolved_fn.aliases[resolved_qualifier]
            fn_revision_id = resolved_alias.revision_id
        # Assumes that a non-alias is a version
        else:
            resolved_version = resolved_fn.versions[resolved_qualifier]
            fn_revision_id = resolved_version.config.revision_id

        return GetPolicyResponse(
            Policy=json.dumps(dataclasses.asdict(function_permission.policy)),
            RevisionId=fn_revision_id,
        )

    # =======================================
    # ========  Code signing config  ========
    # =======================================

    def create_code_signing_config(
        self,
        context: RequestContext,
        allowed_publishers: AllowedPublishers,
        description: Description = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> CreateCodeSigningConfigResponse:

        state = lambda_stores[context.account_id][context.region]
        # TODO: can there be duplicates?
        csc_id = f"csc-{get_random_hex(17)}"  # e.g. 'csc-077c33b4c19e26036'
        csc_arn = (
            f"arn:aws:lambda:{context.region}:{context.account_id}:code-signing-config:{csc_id}"
        )
        csc = CodeSigningConfig(
            csc_id=csc_id,
            arn=csc_arn,
            allowed_publishers=allowed_publishers,
            policies=code_signing_policies,
            last_modified=api_utils.generate_lambda_date(),
            description=description,
        )
        state.code_signing_configs[csc_arn] = csc
        return CreateCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(csc))

    def put_function_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        function_name: FunctionName,
    ) -> PutFunctionCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name, context)

        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise CodeSigningConfigNotFoundException(
                f"The code signing configuration cannot be found. Check that the provided configuration is not deleted: {code_signing_config_arn}.",
                Type="User",
            )

        fn = state.functions.get(function_name)
        fn_arn = api_utils.unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        fn.code_signing_config_arn = code_signing_config_arn
        return PutFunctionCodeSigningConfigResponse(
            CodeSigningConfigArn=code_signing_config_arn, FunctionName=function_name
        )

    def update_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        description: Description = None,
        allowed_publishers: AllowedPublishers = None,
        code_signing_policies: CodeSigningPolicies = None,
    ) -> UpdateCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        changes = {
            **(
                {"allowed_publishers": allowed_publishers} if allowed_publishers is not None else {}
            ),
            **({"policies": code_signing_policies} if code_signing_policies is not None else {}),
            **({"description": description} if description is not None else {}),
        }
        new_csc = dataclasses.replace(
            csc, last_modified=api_utils.generate_lambda_date(), **changes
        )
        state.code_signing_configs[code_signing_config_arn] = new_csc

        return UpdateCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(new_csc))

    def get_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> GetCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        return GetCodeSigningConfigResponse(CodeSigningConfig=api_utils.map_csc(csc))

    def get_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name, context)
        fn = state.functions.get(function_name)
        fn_arn = api_utils.unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        if fn.code_signing_config_arn:
            return GetFunctionCodeSigningConfigResponse(
                CodeSigningConfigArn=fn.code_signing_config_arn, FunctionName=function_name
            )

        return GetFunctionCodeSigningConfigResponse()

    def delete_function_code_signing_config(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        state = lambda_stores[context.account_id][context.region]
        function_name = api_utils.get_function_name(function_name, context)
        fn = state.functions.get(function_name)
        fn_arn = api_utils.unqualified_lambda_arn(function_name, context.account_id, context.region)
        if not fn:
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        fn.code_signing_config_arn = None

    def delete_code_signing_config(
        self, context: RequestContext, code_signing_config_arn: CodeSigningConfigArn
    ) -> DeleteCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        csc = state.code_signing_configs.get(code_signing_config_arn)
        if not csc:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        del state.code_signing_configs[code_signing_config_arn]

        return DeleteCodeSigningConfigResponse()

    def list_code_signing_configs(
        self, context: RequestContext, marker: String = None, max_items: MaxListItems = None
    ) -> ListCodeSigningConfigsResponse:
        state = lambda_stores[context.account_id][context.region]

        cscs = [api_utils.map_csc(csc) for csc in state.code_signing_configs.values()]
        cscs = PaginatedList(cscs)
        page, token = cscs.get_page(
            lambda csc: csc["CodeSigningConfigId"],
            marker,
            max_items,
        )
        return ListCodeSigningConfigsResponse(CodeSigningConfigs=page, NextMarker=token)

    def list_functions_by_code_signing_config(
        self,
        context: RequestContext,
        code_signing_config_arn: CodeSigningConfigArn,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListFunctionsByCodeSigningConfigResponse:
        state = lambda_stores[context.account_id][context.region]

        if code_signing_config_arn not in state.code_signing_configs:
            raise ResourceNotFoundException(
                f"The Lambda code signing configuration {code_signing_config_arn} can not be found."
            )

        fn_arns = [
            api_utils.unqualified_lambda_arn(fn.function_name, context.account_id, context.region)
            for fn in state.functions.values()
            if fn.code_signing_config_arn == code_signing_config_arn
        ]

        cscs = PaginatedList(fn_arns)
        page, token = cscs.get_page(
            lambda x: x,
            marker,
            max_items,
        )
        return ListFunctionsByCodeSigningConfigResponse(FunctionArns=page, NextMarker=token)

    # =======================================
    # =========  Account Settings   =========
    # =======================================

    # CAVE: these settings & usages are *per* region!
    def get_account_settings(
        self,
        context: RequestContext,
    ) -> GetAccountSettingsResponse:
        state = lambda_stores[context.account_id][context.region]

        fn_count = 0
        code_size_sum = 0
        reserved_concurrency_sum = 0
        for fn in state.functions.values():
            fn_count += 1
            for fn_version in fn.versions.values():
                code_size_sum += fn_version.config.code.code_size
            if fn.reserved_concurrent_executions is not None:
                reserved_concurrency_sum += fn.reserved_concurrent_executions
            for c in fn.provisioned_concurrency_configs.values():
                reserved_concurrency_sum += c.provisioned_concurrent_executions
        for layer in state.layers.values():
            for layer_version in layer.layer_versions.values():
                code_size_sum += layer_version.code.code_size
        return GetAccountSettingsResponse(
            AccountLimit=AccountLimit(
                TotalCodeSize=config.LAMBDA_LIMITS_TOTAL_CODE_SIZE,
                CodeSizeZipped=config.LAMBDA_LIMITS_CODE_SIZE_ZIPPED,
                CodeSizeUnzipped=config.LAMBDA_LIMITS_CODE_SIZE_UNZIPPED,
                ConcurrentExecutions=config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS,
                UnreservedConcurrentExecutions=config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS
                - reserved_concurrency_sum,
            ),
            AccountUsage=AccountUsage(
                TotalCodeSize=code_size_sum,
                FunctionCount=fn_count,
            ),
        )

    # =======================================
    # ==  Provisioned Concurrency Config   ==
    # =======================================

    def _get_provisioned_config(
        self, context: RequestContext, function_name: str, qualifier: str
    ) -> ProvisionedConcurrencyConfiguration | None:
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        if api_utils.qualifier_is_alias(qualifier):
            fn_alias = None
            if fn:
                fn_alias = fn.aliases.get(qualifier)
            if fn_alias is None:
                raise ResourceNotFoundException(
                    f"Cannot find alias arn: {api_utils.qualified_lambda_arn(function_name, qualifier, context.account_id, context.region)}",
                    Type="User",
                )
        elif api_utils.qualifier_is_version(qualifier):
            fn_version = None
            if fn:
                fn_version = fn.versions.get(qualifier)
            if fn_version is None:
                raise ResourceNotFoundException(
                    f"Function not found: {api_utils.qualified_lambda_arn(function_name, qualifier, context.account_id, context.region)}",
                    Type="User",
                )

        return fn.provisioned_concurrency_configs.get(qualifier)

    def put_provisioned_concurrency_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier,
        provisioned_concurrent_executions: PositiveInteger,
    ) -> PutProvisionedConcurrencyConfigResponse:
        if provisioned_concurrent_executions <= 0:
            raise ValidationException(
                f"1 validation error detected: Value '{provisioned_concurrent_executions}' at 'provisionedConcurrentExecutions' failed to satisfy constraint: Member must have value greater than or equal to 1"
            )

        if qualifier == "$LATEST":
            raise InvalidParameterValueException(
                "Provisioned Concurrency Configs cannot be applied to unpublished function versions.",
                Type="User",
            )

        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)

        provisioned_config = self._get_provisioned_config(context, function_name, qualifier)

        if provisioned_config:  # TODO: merge?
            # TODO: add a test for partial updates (if possible)
            LOG.warning(
                "Partial update of provisioned concurrency config is currently not supported."
            )

        other_provisioned_sum = sum(
            [
                provisioned_configs.provisioned_concurrent_executions
                for provisioned_qualifier, provisioned_configs in fn.provisioned_concurrency_configs.items()
                if provisioned_qualifier != qualifier
            ]
        )

        if (
            fn.reserved_concurrent_executions is not None
            and fn.reserved_concurrent_executions
            < other_provisioned_sum + provisioned_concurrent_executions
        ):
            raise InvalidParameterValueException(
                "Requested Provisioned Concurrency should not be greater than the reservedConcurrentExecution for function",
                Type="User",
            )

        if provisioned_concurrent_executions > config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS:
            raise InvalidParameterValueException(
                f"Specified ConcurrentExecutions for function is greater than account's unreserved concurrency"
                f" [{config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS}]."
            )

        settings = self.get_account_settings(context)
        unreserved_concurrent_executions = settings["AccountLimit"][
            "UnreservedConcurrentExecutions"
        ]
        if (
            provisioned_concurrent_executions
            > unreserved_concurrent_executions - config.LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY
        ):
            raise InvalidParameterValueException(
                f"Specified ConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below"
                f" its minimum value of [{config.LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY}]."
            )

        provisioned_config = ProvisionedConcurrencyConfiguration(
            provisioned_concurrent_executions, api_utils.generate_lambda_date()
        )
        fn_arn = api_utils.qualified_lambda_arn(
            function_name, qualifier, context.account_id, context.region
        )

        if api_utils.qualifier_is_alias(qualifier):
            alias = fn.aliases.get(qualifier)
            resolved_version = fn.versions.get(alias.function_version)

            if (
                resolved_version
                and fn.provisioned_concurrency_configs.get(alias.function_version) is not None
            ):
                raise ResourceConflictException(
                    "Alias can't be used for Provisioned Concurrency configuration on an already Provisioned version",
                    Type="User",
                )
            fn_arn = resolved_version.id.qualified_arn()
        elif api_utils.qualifier_is_version(qualifier):
            fn_version = fn.versions.get(qualifier)

            # TODO: might be useful other places, utilize
            pointing_aliases = []
            for alias in fn.aliases.values():
                if (
                    alias.function_version == qualifier
                    and fn.provisioned_concurrency_configs.get(alias.name) is not None
                ):
                    pointing_aliases.append(alias.name)
            if pointing_aliases:
                raise ResourceConflictException(
                    "Version is pointed by a Provisioned Concurrency alias", Type="User"
                )

            fn_arn = fn_version.id.qualified_arn()

        manager = self.lambda_service.get_lambda_version_manager(fn_arn)

        fn.provisioned_concurrency_configs[qualifier] = provisioned_config

        manager.update_provisioned_concurrency_config(
            provisioned_config.provisioned_concurrent_executions
        )

        return PutProvisionedConcurrencyConfigResponse(
            RequestedProvisionedConcurrentExecutions=provisioned_config.provisioned_concurrent_executions,
            AvailableProvisionedConcurrentExecutions=0,
            AllocatedProvisionedConcurrentExecutions=0,
            Status=ProvisionedConcurrencyStatusEnum.IN_PROGRESS,
            # StatusReason=manager.provisioned_state.status_reason,
            LastModified=provisioned_config.last_modified,  # TODO: does change with configuration or also with state changes?
        )

    def get_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> GetProvisionedConcurrencyConfigResponse:
        if qualifier == "$LATEST":
            raise InvalidParameterValueException(
                "The function resource provided must be an alias or a published version.",
                Type="User",
            )
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )

        provisioned_config = self._get_provisioned_config(context, function_name, qualifier)
        if not provisioned_config:
            raise ProvisionedConcurrencyConfigNotFoundException(
                "No Provisioned Concurrency Config found for this function", Type="User"
            )

        # TODO: make this compatible with alias pointer migration on update
        if api_utils.qualifier_is_alias(qualifier):
            state = lambda_stores[context.account_id][context.region]
            fn = state.functions.get(function_name)
            alias = fn.aliases.get(qualifier)
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, alias.function_version, context.account_id, context.region
            )
        else:
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )

        ver_manager = self.lambda_service.get_lambda_version_manager(fn_arn)

        return GetProvisionedConcurrencyConfigResponse(
            RequestedProvisionedConcurrentExecutions=provisioned_config.provisioned_concurrent_executions,
            LastModified=provisioned_config.last_modified,
            AvailableProvisionedConcurrentExecutions=ver_manager.provisioned_state.available,
            AllocatedProvisionedConcurrentExecutions=ver_manager.provisioned_state.allocated,
            Status=ver_manager.provisioned_state.status,
            StatusReason=ver_manager.provisioned_state.status_reason,
        )

    def list_provisioned_concurrency_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxProvisionedConcurrencyConfigListItems = None,
    ) -> ListProvisionedConcurrencyConfigsResponse:
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        if fn is None:
            raise ResourceNotFoundException(
                f"Function not found: {api_utils.unqualified_lambda_arn(function_name, context.account_id, context.region)}",
                Type="User",
            )

        configs = []
        for qualifier, pc_config in fn.provisioned_concurrency_configs.items():

            if api_utils.qualifier_is_alias(qualifier):
                alias = fn.aliases.get(qualifier)
                fn_arn = api_utils.qualified_lambda_arn(
                    function_name, alias.function_version, context.account_id, context.region
                )
            else:
                fn_arn = api_utils.qualified_lambda_arn(
                    function_name, qualifier, context.account_id, context.region
                )

            manager = self.lambda_service.get_lambda_version_manager(fn_arn)

            configs.append(
                ProvisionedConcurrencyConfigListItem(
                    FunctionArn=api_utils.qualified_lambda_arn(
                        function_name, qualifier, context.account_id, context.region
                    ),
                    RequestedProvisionedConcurrentExecutions=pc_config.provisioned_concurrent_executions,
                    AvailableProvisionedConcurrentExecutions=manager.provisioned_state.available,
                    AllocatedProvisionedConcurrentExecutions=manager.provisioned_state.allocated,
                    Status=manager.provisioned_state.status,
                    StatusReason=manager.provisioned_state.status_reason,
                    LastModified=pc_config.last_modified,
                )
            )

        provisioned_concurrency_configs = configs
        provisioned_concurrency_configs = PaginatedList(provisioned_concurrency_configs)
        page, token = provisioned_concurrency_configs.get_page(
            lambda x: x,
            marker,
            max_items,
        )
        return ListProvisionedConcurrencyConfigsResponse(
            ProvisionedConcurrencyConfigs=page, NextMarker=token
        )

    def delete_provisioned_concurrency_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier
    ) -> None:
        if qualifier == "$LATEST":
            raise InvalidParameterValueException(
                "The function resource provided must be an alias or a published version.",
                Type="User",
            )
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)

        provisioned_config = self._get_provisioned_config(context, function_name, qualifier)
        # delete is idempotent and doesn't actually care about the provisioned concurrency config not existing
        if provisioned_config:
            fn.provisioned_concurrency_configs.pop(qualifier)
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )
            manager = self.lambda_service.get_lambda_version_manager(fn_arn)
            manager.update_provisioned_concurrency_config(0)

    # =======================================
    # =======  Event Invoke Config   ========
    # =======================================

    # "1 validation error detected: Value 'arn:aws:_-/!lambda:<region>:111111111111:function:<function-name:1>' at 'destinationConfig.onFailure.destination' failed to satisfy constraint: Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\\-])+:([a-z]{2}((-gov)|(-iso(b?)))?-[a-z]+-\\d{1})?:(\\d{12})?:(.*)"
    # "1 validation error detected: Value 'arn:aws:_-/!lambda:<region>:111111111111:function:<function-name:1>' at 'destinationConfig.onFailure.destination' failed to satisfy constraint: Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\\-])+:([a-z]2((-gov)|(-iso(b?)))?-[a-z]+-\\d1)?:(\\d12)?:(.*)" ... (expected → actual)

    def _validate_destination_config(
        self, store: LambdaStore, function_name: str, destination_config: DestinationConfig
    ):
        def _validate_destination_arn(destination_arn) -> bool:
            if not api_utils.DESTINATION_ARN_PATTERN.match(destination_arn):
                # technically we shouldn't handle this in the provider
                raise ValidationException(
                    "1 validation error detected: Value '"
                    + destination_arn
                    + r"' at 'destinationConfig.onFailure.destination' failed to satisfy constraint: Member must satisfy regular expression pattern: ^$|arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}((-gov)|(-iso(b?)))?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
                )

            match destination_arn.split(":")[2]:
                case "lambda":
                    fn_parts = api_utils.FULL_FN_ARN_PATTERN.search(destination_arn).groupdict()
                    if fn_parts:
                        # check if it exists
                        fn = store.functions.get(fn_parts["function_name"])
                        if not fn:
                            raise InvalidParameterValueException(
                                f"The destination ARN {destination_arn} is invalid.", Type="User"
                            )
                        if fn_parts["function_name"] == function_name:
                            raise InvalidParameterValueException(
                                "You can't specify the function as a destination for itself.",
                                Type="User",
                            )
                case "sns" | "sqs" | "events":
                    pass
                case _:
                    return False
            return True

        validation_err = False

        failure_destination = destination_config.get("OnFailure", {}).get("Destination")
        if failure_destination:
            validation_err = validation_err or not _validate_destination_arn(failure_destination)

        success_destination = destination_config.get("OnSuccess", {}).get("Destination")
        if success_destination:
            validation_err = validation_err or not _validate_destination_arn(success_destination)

        if validation_err:
            on_success_part = (
                f"OnSuccess(destination={success_destination})" if success_destination else "null"
            )
            on_failure_part = (
                f"OnFailure(destination={failure_destination})" if failure_destination else "null"
            )
            raise InvalidParameterValueException(
                f"The provided destination config DestinationConfig(onSuccess={on_success_part}, onFailure={on_failure_part}) is invalid.",
                Type="User",
            )

    def put_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        """
        Destination ARNs can be:
        * SQS arn
        * SNS arn
        * Lambda arn
        * EventBridge arn

        Differences between put_ and update_:
            * put overwrites any existing config
            * update allows changes only single values while keeping the rest of existing ones
            * update fails on non-existing configs

        Differences between destination and DLQ
            * "However, a dead-letter queue is part of a function's version-specific configuration, so it is locked in when you publish a version."
            *  "On-failure destinations also support additional targets and include details about the function's response in the invocation record."

        """
        if (
            maximum_event_age_in_seconds is None
            and maximum_retry_attempts is None
            and destination_config is None
        ):
            raise InvalidParameterValueException(
                "You must specify at least one of error handling or destination setting.",
                Type="User",
            )

        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        fn = state.functions.get(function_name)
        if not fn or (qualifier and not (qualifier in fn.aliases or qualifier in fn.versions)):
            raise ResourceNotFoundException("The function doesn't exist.", Type="User")

        qualifier = qualifier or "$LATEST"

        # validate and normalize destination config
        if destination_config:
            self._validate_destination_config(state, function_name, destination_config)

        destination_config = DestinationConfig(
            OnSuccess=OnSuccess(
                Destination=(destination_config or {}).get("OnSuccess", {}).get("Destination")
            ),
            OnFailure=OnFailure(
                Destination=(destination_config or {}).get("OnFailure", {}).get("Destination")
            ),
        )

        config = EventInvokeConfig(
            function_name=function_name,
            qualifier=qualifier,
            maximum_event_age_in_seconds=maximum_event_age_in_seconds,
            maximum_retry_attempts=maximum_retry_attempts,
            last_modified=api_utils.generate_lambda_date(),
            destination_config=destination_config,
        )
        fn.event_invoke_configs[qualifier] = config

        return FunctionEventInvokeConfig(
            LastModified=datetime.datetime.strptime(
                config.last_modified, api_utils.LAMBDA_DATE_FORMAT
            ),
            FunctionArn=api_utils.qualified_lambda_arn(
                function_name, qualifier or "$LATEST", context.account_id, context.region
            ),
            DestinationConfig=destination_config,
            MaximumEventAgeInSeconds=maximum_event_age_in_seconds,
            MaximumRetryAttempts=maximum_retry_attempts,
        )

    def get_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> FunctionEventInvokeConfig:
        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )

        qualifier = qualifier or "$LATEST"
        fn = state.functions.get(function_name)
        if not fn:
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )
            raise ResourceNotFoundException(
                f"The function {fn_arn} doesn't have an EventInvokeConfig", Type="User"
            )

        config = fn.event_invoke_configs.get(qualifier)
        if not config:
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )
            raise ResourceNotFoundException(
                f"The function {fn_arn} doesn't have an EventInvokeConfig", Type="User"
            )

        return FunctionEventInvokeConfig(
            LastModified=datetime.datetime.strptime(
                config.last_modified, api_utils.LAMBDA_DATE_FORMAT
            ),
            FunctionArn=api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            ),
            DestinationConfig=config.destination_config,
            MaximumEventAgeInSeconds=config.maximum_event_age_in_seconds,
            MaximumRetryAttempts=config.maximum_retry_attempts,
        )

    def list_function_event_invoke_configs(
        self,
        context: RequestContext,
        function_name: FunctionName,
        marker: String = None,
        max_items: MaxFunctionEventInvokeConfigListItems = None,
    ) -> ListFunctionEventInvokeConfigsResponse:
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        if not fn:
            raise ResourceNotFoundException("The function doesn't exist.", Type="User")

        event_invoke_configs = [
            FunctionEventInvokeConfig(
                LastModified=c.last_modified,
                FunctionArn=api_utils.qualified_lambda_arn(
                    function_name, c.qualifier, context.account_id, context.region
                ),
                MaximumEventAgeInSeconds=c.maximum_event_age_in_seconds,
                MaximumRetryAttempts=c.maximum_retry_attempts,
                DestinationConfig=c.destination_config,
            )
            for c in fn.event_invoke_configs.values()
        ]

        event_invoke_configs = PaginatedList(event_invoke_configs)
        page, token = event_invoke_configs.get_page(
            lambda x: x["FunctionArn"],
            marker,
            max_items,
        )
        return ListFunctionEventInvokeConfigsResponse(
            FunctionEventInvokeConfigs=page, NextMarker=token
        )

    def delete_function_event_invoke_config(
        self, context: RequestContext, function_name: FunctionName, qualifier: Qualifier = None
    ) -> None:
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )
        state = lambda_stores[context.account_id][context.region]
        fn = state.functions.get(function_name)
        resolved_qualifier = qualifier or "$LATEST"
        fn_arn = api_utils.qualified_lambda_arn(
            function_name, qualifier, context.account_id, context.region
        )
        if not fn:
            raise ResourceNotFoundException(
                f"The function {fn_arn} doesn't have an EventInvokeConfig", Type="User"
            )

        config = fn.event_invoke_configs.get(resolved_qualifier)
        if not config:
            raise ResourceNotFoundException(
                f"The function {fn_arn} doesn't have an EventInvokeConfig", Type="User"
            )

        del fn.event_invoke_configs[resolved_qualifier]

    def update_function_event_invoke_config(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
        maximum_retry_attempts: MaximumRetryAttempts = None,
        maximum_event_age_in_seconds: MaximumEventAgeInSeconds = None,
        destination_config: DestinationConfig = None,
    ) -> FunctionEventInvokeConfig:
        # like put but only update single fields via replace
        state = lambda_stores[context.account_id][context.region]
        function_name, qualifier = api_utils.get_name_and_qualifier(
            function_name, qualifier, context
        )

        if (
            maximum_event_age_in_seconds is None
            and maximum_retry_attempts is None
            and destination_config is None
        ):
            raise InvalidParameterValueException(
                "You must specify at least one of error handling or destination setting.",
                Type="User",
            )

        fn = state.functions.get(function_name)
        if not fn or (qualifier and not (qualifier in fn.aliases or qualifier in fn.versions)):
            raise ResourceNotFoundException("The function doesn't exist.", Type="User")

        qualifier = qualifier or "$LATEST"

        config = fn.event_invoke_configs.get(qualifier)
        if not config:
            fn_arn = api_utils.qualified_lambda_arn(
                function_name, qualifier, context.account_id, context.region
            )
            raise ResourceNotFoundException(
                f"The function {fn_arn} doesn't have an EventInvokeConfig", Type="User"
            )

        if destination_config:
            self._validate_destination_config(state, function_name, destination_config)

        optional_kwargs = {
            k: v
            for k, v in {
                "destination_config": destination_config,
                "maximum_retry_attempts": maximum_retry_attempts,
                "maximum_event_age_in_seconds": maximum_event_age_in_seconds,
            }.items()
            if v is not None
        }

        new_config = dataclasses.replace(
            config, last_modified=api_utils.generate_lambda_date(), **optional_kwargs
        )
        fn.event_invoke_configs[qualifier] = new_config

        return FunctionEventInvokeConfig(
            LastModified=datetime.datetime.strptime(
                new_config.last_modified, api_utils.LAMBDA_DATE_FORMAT
            ),
            FunctionArn=api_utils.qualified_lambda_arn(
                function_name, qualifier or "$LATEST", context.account_id, context.region
            ),
            DestinationConfig=new_config.destination_config,
            MaximumEventAgeInSeconds=new_config.maximum_event_age_in_seconds,
            MaximumRetryAttempts=new_config.maximum_retry_attempts,
        )

    # =======================================
    # ======  Layer & Layer Versions  =======
    # =======================================

    @staticmethod
    def _resolve_layer(
        layer_name_or_arn: str, context: RequestContext
    ) -> Tuple[str, str, str, Optional[str]]:
        """
        Return locator attributes for a given Lambda layer.

        :param layer_name_or_arn: Layer name or ARN
        :param context: Request context
        :return: Tuple of region, account ID, layer name, layer version
        """
        if api_utils.is_layer_arn(layer_name_or_arn):
            return api_utils.parse_layer_arn(layer_name_or_arn)

        return context.region, context.account_id, layer_name_or_arn, None

    def publish_layer_version(
        self,
        context: RequestContext,
        layer_name: LayerName,
        content: LayerVersionContentInput,
        description: Description = None,
        compatible_runtimes: CompatibleRuntimes = None,
        license_info: LicenseInfo = None,
        compatible_architectures: CompatibleArchitectures = None,
    ) -> PublishLayerVersionResponse:
        """
        On first use of a LayerName a new layer is created and for each subsequent call with the same LayerName a new version is created.
        Note that there are no $LATEST versions with layers!

        """
        validation_errors = api_utils.validate_layer_runtimes_and_architectures(
            compatible_runtimes, compatible_architectures
        )
        if validation_errors:
            raise ValidationException(
                f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {'; '.join(validation_errors)}"
            )

        state = lambda_stores[context.account_id][context.region]
        with self.create_layer_lock:
            if layer_name not in state.layers:
                # we don't have a version so create new layer object
                # lock is required to avoid creating two v1 objects for the same name
                layer = Layer(
                    arn=api_utils.layer_arn(
                        layer_name=layer_name, account=context.account_id, region=context.region
                    )
                )
                state.layers[layer_name] = layer

        layer = state.layers[layer_name]
        with layer.next_version_lock:
            next_version = layer.next_version
            layer.next_version += 1

        # creating a new layer
        if content.get("ZipFile"):
            code = store_lambda_archive(
                archive_file=content["ZipFile"],
                function_name=layer_name,
                region_name=context.region,
                account_id=context.account_id,
            )
        else:
            code = store_s3_bucket_archive(
                archive_bucket=content["S3Bucket"],
                archive_key=content["S3Key"],
                archive_version=content.get("S3ObjectVersion"),
                function_name=layer_name,
                region_name=context.region,
                account_id=context.account_id,
            )

        new_layer_version = LayerVersion(
            layer_version_arn=api_utils.layer_version_arn(
                layer_name=layer_name,
                account=context.account_id,
                region=context.region,
                version=str(next_version),
            ),
            layer_arn=layer.arn,
            version=next_version,
            description=description or "",
            license_info=license_info,
            compatible_runtimes=compatible_runtimes,
            compatible_architectures=compatible_architectures,
            created=api_utils.generate_lambda_date(),
            code=code,
        )

        layer.layer_versions[str(next_version)] = new_layer_version

        return api_utils.map_layer_out(new_layer_version)

    def get_layer_version(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> GetLayerVersionResponse:
        # TODO: handle layer_name as an ARN

        region_name, account_id, layer_name, _ = LambdaProvider._resolve_layer(layer_name, context)
        state = lambda_stores[account_id][region_name]

        layer = state.layers.get(layer_name)
        if version_number < 1:
            raise InvalidParameterValueException("Layer Version Cannot be less than 1", Type="User")
        if layer is None:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        layer_version = layer.layer_versions.get(str(version_number))
        if layer_version is None:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )
        return api_utils.map_layer_out(layer_version)

    def get_layer_version_by_arn(
        self, context: RequestContext, arn: LayerVersionArn
    ) -> GetLayerVersionResponse:
        region_name, account_id, layer_name, layer_version = LambdaProvider._resolve_layer(
            arn, context
        )

        if not layer_version:
            raise ValidationException(
                f"1 validation error detected: Value '{arn}' at 'arn' failed to satisfy constraint: Member must satisfy regular expression pattern: "
                + "arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}((-gov)|(-iso(b?)))?-[a-z]+-\\d{1}:\\d{12}:layer:[a-zA-Z0-9-_]+:[0-9]+"
            )

        store = lambda_stores[account_id][region_name]
        layer_version = store.layers.get(layer_name, {}).layer_versions.get(layer_version)

        if not layer_version:
            raise ResourceNotFoundException(
                "The resource you requested does not exist.", Type="User"
            )

        return api_utils.map_layer_out(layer_version)

    def list_layers(
        self,
        context: RequestContext,
        compatible_runtime: Runtime = None,
        marker: String = None,
        max_items: MaxLayerListItems = None,
        compatible_architecture: Architecture = None,
    ) -> ListLayersResponse:
        validation_errors = []

        validation_error_arch = api_utils.validate_layer_architecture(compatible_architecture)
        if validation_error_arch:
            validation_errors.append(validation_error_arch)

        validation_error_runtime = api_utils.validate_layer_runtime(compatible_runtime)
        if validation_error_runtime:
            validation_errors.append(validation_error_runtime)

        if validation_errors:
            raise ValidationException(
                f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {';'.join(validation_errors)}"
            )
        # TODO: handle filter: compatible_runtime
        # TODO: handle filter: compatible_architecture

        state = lambda_stores[context.account_id][context.region]
        layers = state.layers

        # TODO: test how filters behave together with only returning layers here? Does it return the latest "matching" layer, i.e. does it ignore later layer versions that don't match?

        responses: list[LayersListItem] = []
        for layer_name, layer in layers.items():
            # fetch latest version
            layer_versions = list(layer.layer_versions.values())
            sorted(layer_versions, key=lambda x: x.version)
            latest_layer_version = layer_versions[-1]
            responses.append(
                LayersListItem(
                    LayerName=layer_name,
                    LayerArn=layer.arn,
                    LatestMatchingVersion=api_utils.map_layer_out(latest_layer_version),
                )
            )

        responses = PaginatedList(responses)
        page, token = responses.get_page(
            lambda version: version,
            marker,
            max_items,
        )

        return ListLayersResponse(NextMarker=token, Layers=page)

    def list_layer_versions(
        self,
        context: RequestContext,
        layer_name: LayerName,
        compatible_runtime: Runtime = None,
        marker: String = None,
        max_items: MaxLayerListItems = None,
        compatible_architecture: Architecture = None,
    ) -> ListLayerVersionsResponse:
        validation_errors = api_utils.validate_layer_runtimes_and_architectures(
            [compatible_runtime] if compatible_runtime else [],
            [compatible_architecture] if compatible_architecture else [],
        )
        if validation_errors:
            raise ValidationException(
                f"{len(validation_errors)} validation error{'s' if len(validation_errors) > 1 else ''} detected: {';'.join(validation_errors)}"
            )

        region_name, account_id, layer_name, layer_version = LambdaProvider._resolve_layer(
            layer_name, context
        )
        state = lambda_stores[account_id][region_name]

        # TODO: Test & handle filter: compatible_runtime
        # TODO: Test & handle filter: compatible_architecture
        all_layer_versions = []
        layer = state.layers.get(layer_name)
        if layer is not None:
            for layer_version in layer.layer_versions.values():
                all_layer_versions.append(api_utils.map_layer_out(layer_version))

        all_layer_versions.sort(key=lambda x: x["Version"], reverse=True)
        all_layer_versions = PaginatedList(all_layer_versions)
        page, token = all_layer_versions.get_page(
            lambda version: version["LayerVersionArn"],
            marker,
            max_items,
        )
        return ListLayerVersionsResponse(NextMarker=token, LayerVersions=page)

    def delete_layer_version(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> None:
        if version_number < 1:
            raise InvalidParameterValueException("Layer Version Cannot be less than 1", Type="User")

        region_name, account_id, layer_name, layer_version = LambdaProvider._resolve_layer(
            layer_name, context
        )

        store = lambda_stores[account_id][region_name]
        layer = store.layers.get(layer_name, {})
        if layer:
            layer.layer_versions.pop(str(version_number), None)

    # =======================================
    # =====  Layer Version Permissions  =====
    # =======================================
    # TODO: lock updates that change revision IDs

    def add_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        action: LayerPermissionAllowedAction,
        principal: LayerPermissionAllowedPrincipal,
        organization_id: OrganizationId = None,
        revision_id: String = None,
    ) -> AddLayerVersionPermissionResponse:
        # `layer_name` can either be layer name or ARN. It is used to generate error messages.
        # `layer_n` contains the layer name.
        region_name, account_id, layer_n, _ = LambdaProvider._resolve_layer(layer_name, context)

        if action != "lambda:GetLayerVersion":
            raise ValidationException(
                f"1 validation error detected: Value '{action}' at 'action' failed to satisfy constraint: Member must satisfy regular expression pattern: lambda:GetLayerVersion"
            )

        store = lambda_stores[account_id][region_name]
        layer = store.layers.get(layer_n)

        layer_version_arn = api_utils.layer_version_arn(
            layer_name, account_id, region_name, str(version_number)
        )

        if layer is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )
        layer_version = layer.layer_versions.get(str(version_number))
        if layer_version is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )
        # do we have a policy? if not set one
        if layer_version.policy is None:
            layer_version.policy = LayerPolicy()

        if statement_id in layer_version.policy.statements:
            raise ResourceConflictException(
                f"The statement id ({statement_id}) provided already exists. Please provide a new statement id, or remove the existing statement.",
                Type="User",
            )

        if revision_id and layer_version.policy.revision_id != revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetLayerPolicy API to retrieve the latest Revision Id",
                Type="User",
            )

        statement = LayerPolicyStatement(
            sid=statement_id, action=action, principal=principal, organization_id=organization_id
        )

        old_statements = layer_version.policy.statements
        layer_version.policy = dataclasses.replace(
            layer_version.policy, statements={**old_statements, statement_id: statement}
        )

        return AddLayerVersionPermissionResponse(
            Statement=json.dumps(
                {
                    "Sid": statement.sid,
                    "Effect": "Allow",
                    "Principal": statement.principal,
                    "Action": statement.action,
                    "Resource": layer_version.layer_version_arn,
                }
            ),
            RevisionId=layer_version.policy.revision_id,
        )

    def remove_layer_version_permission(
        self,
        context: RequestContext,
        layer_name: LayerName,
        version_number: LayerVersionNumber,
        statement_id: StatementId,
        revision_id: String = None,
    ) -> None:
        # `layer_name` can either be layer name or ARN. It is used to generate error messages.
        # `layer_n` contains the layer name.
        region_name, account_id, layer_n, layer_version = LambdaProvider._resolve_layer(
            layer_name, context
        )

        layer_version_arn = api_utils.layer_version_arn(
            layer_name, account_id, region_name, str(version_number)
        )

        state = lambda_stores[account_id][region_name]
        layer = state.layers.get(layer_n)
        if layer is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )
        layer_version = layer.layer_versions.get(str(version_number))
        if layer_version is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )

        if revision_id and layer_version.policy.revision_id != revision_id:
            raise PreconditionFailedException(
                "The Revision Id provided does not match the latest Revision Id. "
                "Call the GetLayerPolicy API to retrieve the latest Revision Id",
                Type="User",
            )

        if statement_id not in layer_version.policy.statements:
            raise ResourceNotFoundException(
                f"Statement {statement_id} is not found in resource policy.", Type="User"
            )

        old_statements = layer_version.policy.statements
        layer_version.policy = dataclasses.replace(
            layer_version.policy,
            statements={k: v for k, v in old_statements.items() if k != statement_id},
        )

    def get_layer_version_policy(
        self, context: RequestContext, layer_name: LayerName, version_number: LayerVersionNumber
    ) -> GetLayerVersionPolicyResponse:
        # `layer_name` can either be layer name or ARN. It is used to generate error messages.
        # `layer_n` contains the layer name.
        region_name, account_id, layer_n, _ = LambdaProvider._resolve_layer(layer_name, context)

        layer_version_arn = api_utils.layer_version_arn(
            layer_name, account_id, region_name, str(version_number)
        )

        store = lambda_stores[account_id][region_name]
        layer = store.layers.get(layer_n)

        if layer is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )

        layer_version = layer.layer_versions.get(str(version_number))
        if layer_version is None:
            raise ResourceNotFoundException(
                f"Layer version {layer_version_arn} does not exist.", Type="User"
            )

        if layer_version.policy is None:
            raise ResourceNotFoundException(
                "No policy is associated with the given resource.", Type="User"
            )

        return GetLayerVersionPolicyResponse(
            Policy=json.dumps(
                {
                    "Version": layer_version.policy.version,
                    "Id": layer_version.policy.id,
                    "Statement": [
                        {
                            "Sid": ps.sid,
                            "Effect": "Allow",
                            "Principal": ps.principal,
                            "Action": ps.action,
                            "Resource": layer_version.layer_version_arn,
                        }
                        for ps in layer_version.policy.statements.values()
                    ],
                }
            ),
            RevisionId=layer_version.policy.revision_id,
        )

    # =======================================
    # =======  Function Concurrency  ========
    # =======================================
    # (Reserved) function concurrency is scoped to the whole function

    def get_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> GetFunctionConcurrencyResponse:
        function_name = api_utils.get_function_name(function_name, context)
        fn = self._get_function(
            function_name=function_name, region=context.region, account_id=context.account_id
        )
        return GetFunctionConcurrencyResponse(
            ReservedConcurrentExecutions=fn.reserved_concurrent_executions
        )

    def put_function_concurrency(
        self,
        context: RequestContext,
        function_name: FunctionName,
        reserved_concurrent_executions: ReservedConcurrentExecutions,
    ) -> Concurrency:
        account_id, region = api_utils.get_account_and_region(function_name, context)

        function_name, qualifier = api_utils.get_name_and_qualifier(function_name, None, context)
        if qualifier:
            raise InvalidParameterValueException(
                "This operation is permitted on Lambda functions only. Aliases and versions do not support this operation. Please specify either a function name or an unqualified function ARN.",
                Type="User",
            )

        store = lambda_stores[account_id][region]
        fn = store.functions.get(function_name)
        if not fn:
            fn_arn = api_utils.qualified_lambda_arn(
                function_name,
                qualifier="$LATEST",
                account=account_id,
                region=region,
            )
            raise ResourceNotFoundException(f"Function not found: {fn_arn}", Type="User")

        settings = self.get_account_settings(context)
        unreserved_concurrent_executions = settings["AccountLimit"][
            "UnreservedConcurrentExecutions"
        ]

        if (
            unreserved_concurrent_executions - reserved_concurrent_executions
        ) < config.LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY:
            raise InvalidParameterValueException(
                f"Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [{config.LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY}]."
            )

        total_provisioned_concurrency = sum(
            [
                provisioned_configs.provisioned_concurrent_executions
                for provisioned_configs in fn.provisioned_concurrency_configs.values()
            ]
        )
        if total_provisioned_concurrency > reserved_concurrent_executions:
            raise InvalidParameterValueException(
                f" ReservedConcurrentExecutions  {reserved_concurrent_executions} should not be lower than function's total provisioned concurrency [{total_provisioned_concurrency}]."
            )

        fn.reserved_concurrent_executions = reserved_concurrent_executions

        return Concurrency(ReservedConcurrentExecutions=fn.reserved_concurrent_executions)

    def delete_function_concurrency(
        self, context: RequestContext, function_name: FunctionName
    ) -> None:
        account_id, region = api_utils.get_account_and_region(function_name, context)
        function_name, qualifier = api_utils.get_name_and_qualifier(function_name, None, context)
        store = lambda_stores[account_id][region]
        fn = store.functions.get(function_name)
        fn.reserved_concurrent_executions = None

    # =======================================
    # ===============  TAGS   ===============
    # =======================================
    # only function ARNs are available for tagging

    def _get_tags(self, function: Function) -> dict[str, str]:
        return function.tags or {}

    def _store_tags(self, function: Function, tags: dict[str, str]):
        if len(tags) > LAMBDA_TAG_LIMIT_PER_RESOURCE:
            raise InvalidParameterValueException(
                "Number of tags exceeds function tag limit.", Type="User"
            )
        with function.lock:
            function.tags = tags
            # dirty hack for changed revision id, should reevaluate model to prevent this:
            latest_version = function.versions["$LATEST"]
            function.versions["$LATEST"] = dataclasses.replace(
                latest_version, config=dataclasses.replace(latest_version.config)
            )

    def _update_tags(self, function: Function, tags: dict[str, str]):
        with function.lock:
            stored_tags = function.tags or {}
            stored_tags |= tags
            self._store_tags(function=function, tags=stored_tags)

    def tag_resource(self, context: RequestContext, resource: FunctionArn, tags: Tags) -> None:
        if not tags:
            raise InvalidParameterValueException(
                "An error occurred and the request cannot be processed.", Type="User"
            )

        pattern_match = api_utils.FULL_FN_ARN_PATTERN.search(resource)
        if not pattern_match:
            raise ValidationException(
                rf"1 validation error detected: Value '{resource}' at 'resource' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{{2}}((-gov)|(-iso(b?)))?-[a-z]+-\d{{1}}:\d{{12}}:function:[a-zA-Z0-9-_]+(:(\$LATEST|[a-zA-Z0-9-_]+))?"
            )

        groups = pattern_match.groupdict()
        fn_name = groups.get("function_name")

        if groups.get("qualifier"):
            raise InvalidParameterValueException(
                "Tagging operations are permitted on Lambda functions only. Tags on aliases and versions are not supported. Please specify either a function name or a function ARN.",
                Type="User",
            )

        account_id, region = api_utils.get_account_and_region(resource, context)
        fn = self._get_function(function_name=fn_name, account_id=account_id, region=region)

        self._update_tags(fn, tags)

    def list_tags(self, context: RequestContext, resource: FunctionArn) -> ListTagsResponse:
        account_id, region = api_utils.get_account_and_region(resource, context)
        function_name = api_utils.get_function_name(resource, context)
        fn = self._get_function(function_name=function_name, account_id=account_id, region=region)

        return ListTagsResponse(Tags=self._get_tags(fn))

    def untag_resource(
        self, context: RequestContext, resource: FunctionArn, tag_keys: TagKeyList
    ) -> None:
        if not tag_keys:
            raise ValidationException(
                "1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null"
            )  # should probably be generalized a bit

        account_id, region = api_utils.get_account_and_region(resource, context)
        function_name = api_utils.get_function_name(resource, context)
        fn = self._get_function(function_name=function_name, account_id=account_id, region=region)

        # copy first, then set explicitly in store tags
        tags = dict(fn.tags or {})
        if tags:
            for key in tag_keys:
                if key in tags:
                    tags.pop(key)
        self._store_tags(function=fn, tags=tags)

    # =======================================
    # =======  LEGACY / DEPRECATED   ========
    # =======================================

    def invoke_async(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invoke_args: IO[BlobStream],
    ) -> InvokeAsyncResponse:
        """LEGACY API endpoint. Even AWS heavily discourages its usage."""
        raise NotImplementedError
