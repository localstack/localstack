import base64
import hashlib
import logging
import threading
import time
import uuid

from localstack.aws.api import RequestContext
from localstack.aws.api.awslambda import (
    Alias,
    AliasConfiguration,
    AliasRoutingConfiguration,
    Architecture,
    ArchitecturesList,
    Blob,
    Boolean,
    CodeSigningConfigArn,
    DeadLetterConfig,
    Description,
    Environment,
    FileSystemConfigList,
    FunctionCode,
    FunctionConfiguration,
    FunctionName,
    GetFunctionResponse,
    Handler,
    ImageConfig,
    InvocationResponse,
    InvocationType,
    KMSKeyArn,
    LambdaApi,
    LastUpdateStatus,
    LayerList,
    ListAliasesResponse,
    ListFunctionsResponse,
    LogType,
    MasterRegion,
    MaxListItems,
    MemorySize,
    NamespacedFunctionName,
    PackageType,
    PreconditionFailedException,
    Qualifier,
    ResourceConflictException,
    RoleArn,
    Runtime,
    S3Bucket,
    S3Key,
    S3ObjectVersion,
    ServiceException,
    State,
    String,
    Tags,
    Timeout,
    TracingConfig,
    TracingMode,
    Version,
    VpcConfig,
)
from localstack.services.awslambda.invocation.lambda_service import (
    FunctionVersion,
    LambdaFunction,
    LambdaFunctionVersion,
    LambdaService,
    LambdaServiceBackend,
)
from localstack.services.awslambda.invocation.lambda_util import (
    function_name_from_arn,
    is_qualified_lambda_arn,
    qualified_lambda_arn,
)
from localstack.services.awslambda.lambda_utils import generate_lambda_arn
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.strings import to_bytes, to_str

LAMBDA_DEFAULT_TIMEOUT_SECONDS = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128

LOG = logging.getLogger(__name__)


class LambdaProvider(LambdaApi, ServiceLifecycleHook):

    lambda_service: LambdaService
    lock: threading.RLock

    def __init__(self) -> None:
        self.lambda_service = LambdaService()
        self.lock = threading.RLock()

    def on_before_stop(self) -> None:
        self.lambda_service.stop()

    def create_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn,
        code: FunctionCode,
        runtime: Runtime = None,
        handler: Handler = None,
        description: Description = None,
        timeout: Timeout = None,
        memory_size: MemorySize = None,
        publish: Boolean = None,
        vpc_config: VpcConfig = None,
        package_type: PackageType = None,
        dead_letter_config: DeadLetterConfig = None,
        environment: Environment = None,
        kms_key_arn: KMSKeyArn = None,
        tracing_config: TracingConfig = None,
        tags: Tags = None,
        layers: LayerList = None,
        file_system_configs: FileSystemConfigList = None,
        image_config: ImageConfig = None,
        code_signing_config_arn: CodeSigningConfigArn = None,
        architectures: ArchitecturesList = None,
    ) -> FunctionConfiguration:
        # TODO: setup proper logging structure
        LOG.debug("Creating lambda function with params: %s", dict(locals()))

        if architectures and Architecture.arm64 in architectures:
            raise ServiceException("ARM64 is currently not supported by this provider")

        if not architectures:
            architectures = [Architecture.x86_64]

        if not package_type:
            package_type = PackageType.Zip

        state = LambdaServiceBackend.get()

        # defaults
        qualified_arn = qualified_lambda_arn(
            function_name, "$LATEST", context.account_id, context.region
        )
        env_vars = environment["Variables"] if environment and environment.get("Variables") else {}

        # --- code related parameter handling ---
        # memory_size
        # architectures
        # timeout
        # environment
        # vpc_config
        # TODO: refactor this later since we'll need most of the code again in updates
        code_size = 0  # default
        code_sha_256 = ""  # TODO: verify there's a default
        if package_type == PackageType.Image and code.get("ImageUri") and ImageConfig:
            # container image
            # image_config
            raise ServiceException("PRO feature")  # TODO implement PRO
        else:
            # managed runtime or provided runtime

            # package_type
            # runtime
            # handler
            # layers
            # TODO: handle S3 bucket
            zip_file_content = code.get("ZipFile")
            code_sha_256 = base64.standard_b64encode(
                hashlib.sha256(zip_file_content).digest()
            ).decode("utf-8")
            code_size = len(zip_file_content)

            if runtime in [Runtime.provided, Runtime.provided_al2]:
                # provided runtime
                raise ServiceException("Not implemented")  # TODO
            else:
                # some managed runtime
                pass
            pass

        # creating entities
        # TODO: handle publish option
        f_config = FunctionConfiguration(
            FunctionName=function_name,
            FunctionArn=qualified_arn,
            Runtime=runtime,
            Role=role,
            Handler=handler,
            Environment=environment,
            Description=description or "",
            RevisionId=str(uuid.uuid4()),
            MemorySize=memory_size or LAMBDA_DEFAULT_MEMORY_SIZE,
            Timeout=timeout or LAMBDA_DEFAULT_TIMEOUT_SECONDS,
            CodeSize=code_size,
            CodeSha256=code_sha_256,  # TODO: sure this has a default?
            Version="$LATEST",
            TracingConfig=TracingConfig(Mode=TracingMode.PassThrough),  # TODO
            PackageType=package_type,
            Architectures=architectures,
            # TODO: implement proper status tracking
            LastModified="?",  # TODO
            LastUpdateStatus=LastUpdateStatus.Successful,  # TODO
            # LastUpdateStatusReasonCode=, # TODO
            # LastUpdateStatusReason=, # TODO
            # StateReason="?",  # TODO
            # StateReasonCode=StateReasonCode., # TODO
            State=State.Active,  # TODO
        )

        new_version = LambdaFunctionVersion(f_config, code)
        new_fn = LambdaFunction(latest=new_version)

        # TODO: verify behavior with AWS when creating two functions concurrently (also with publish =true)
        # preventing concurrent "double" setting here
        # due to the GIL this might actually be atomic anyway
        with self.lock:
            if state.functions.get(function_name):
                raise ResourceConflictException(f"Function already exist: {function_name}")

            state.functions[function_name] = new_fn
            if tags:
                state.TAGS.tag_resource(
                    new_fn.latest.config["FunctionArn"], tags=[tags]
                )  # TODO: test
        # TODO: this might have to come after the downstream setup
        if publish:
            with new_fn.lock:
                new_version = self._publish_version(
                    new_fn, description=description
                )  # TODO: not sure if thats the same description

        # TODO: downstream setup (actual lambda provisioning)
        version = FunctionVersion(
            qualified_arn=qualified_arn,
            name=function_name,
            version="$LATEST",
            region=context.region,
            zip_file=code.get("ZipFile"),
            runtime=runtime,
            architecture=Architecture.x86_64,
            role=role,
            environment=env_vars,
            handler=handler,
        )
        self.lambda_service.create_function_version(function_version_definition=version)
        # TODO: when publish=true, should this then be the published version or still $LATEST?
        # yes it does, still needs some test coverage
        return f_config

    def _map_to_list_response(self, config: FunctionConfiguration) -> FunctionConfiguration:
        shallow_copy = config.copy()
        for k in [
            "State",
            "StateReason",
            "StateReasonCode",
            "LastUpdateStatus",
            "LastUpdateStatusReason",
            "LastUpdateStatusReasonCode",
        ]:
            if shallow_copy.get(k):
                del shallow_copy[k]
        return shallow_copy

    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,  # TODO (only relevant for lambda@edge)
        function_version: FunctionVersion = None,  # TODO
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListFunctionsResponse:
        # TODO: limit fields returned
        # TODO: implement paging
        state = LambdaServiceBackend.get()
        return ListFunctionsResponse(
            Functions=[
                self._map_to_list_response(f.latest.config) for f in state.functions.values()
            ]
        )

    def get_function(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,  # TODO
    ) -> GetFunctionResponse:
        state = LambdaServiceBackend.get()
        latest = state.functions.get(function_name).latest
        return GetFunctionResponse(
            Configuration=latest.config,
            Tags=state.TAGS.list_tags_for_resource(function_name),
            Concurrency={},  # TODO
        )

    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType = None,
        log_type: LogType = None,
        client_context: String = None,
        payload: Blob = None,
        qualifier: Qualifier = None,
    ) -> InvocationResponse:
        LOG.debug("Lambda function got invoked! Params: %s", dict(locals()))

        # TODO discuss where function data is stored - might need to be passed here
        qualified_arn = qualified_lambda_arn(
            function_name, "$LATEST", context.account_id, context.region
        )
        time_before = time.perf_counter()
        result = self.lambda_service.invoke(
            function_arn_qualified=qualified_arn,
            invocation_type=invocation_type,
            client_context=client_context,
            payload=payload,
        )
        invocation_result = result.result()
        LOG.debug("Type of result: %s", type(invocation_result))

        function_error = None
        if "error" in str(invocation_result.payload):
            function_error = "Unhandled"

        response = InvocationResponse(
            StatusCode=200,
            Payload=invocation_result.payload,
            ExecutedVersion="$LATEST",  # TODO: should be resolved version from qualifier
            FunctionError=function_error,  # TODO: should be conditional. Might ahve to get this from the invoke result as well
        )
        LOG.debug("Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000)
        LOG.debug("Result: %s", invocation_result)

        if log_type == LogType.Tail:
            response["LogResult"] = to_str(base64.b64encode(to_bytes(invocation_result.logs)))

        return response

    # TODO: does deleting the latest published version affect the next versions number?
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        state = LambdaServiceBackend.get()
        qualified_arn = (
            function_name
            if is_qualified_lambda_arn(function_name)
            else qualified_lambda_arn(
                function_name,
                region=context.region,
                account=context.account_id,
                qualifier=qualifier,
            )
        )
        if qualifier and qualifier != "$LATEST":
            # only delete this version
            pass  # TODO
        else:
            # TODO: this actually first needs to set the state and handle this in the lambda service and all downstream services!
            # TODO: delete all related resources (Aliases, Versions)
            self.lambda_service.stop_version(qualified_arn)
            name = (
                function_name
                if not is_qualified_lambda_arn(function_name)
                else function_name_from_arn(function_name)
            )
            del state.functions[name]

    def update_function_code(
        self,
        context: RequestContext,
        function_name: FunctionName,
        zip_file: Blob = None,
        s3_bucket: S3Bucket = None,
        s3_key: S3Key = None,
        s3_object_version: S3ObjectVersion = None,
        image_uri: String = None,
        publish: Boolean = None,
        dry_run: Boolean = None,
        revision_id: String = None,
        architectures: ArchitecturesList = None,
    ) -> FunctionConfiguration:
        raise ServiceException("Not implemented (yet). Stay tuned!")

    def update_function_configuration(
        self,
        context: RequestContext,
        function_name: FunctionName,
        role: RoleArn = None,
        handler: Handler = None,
        description: Description = None,
        timeout: Timeout = None,
        memory_size: MemorySize = None,
        vpc_config: VpcConfig = None,
        environment: Environment = None,
        runtime: Runtime = None,
        dead_letter_config: DeadLetterConfig = None,
        kms_key_arn: KMSKeyArn = None,
        tracing_config: TracingConfig = None,
        revision_id: String = None,
        layers: LayerList = None,
        file_system_configs: FileSystemConfigList = None,
        image_config: ImageConfig = None,
    ) -> FunctionConfiguration:
        raise ServiceException("Not implemented (yet). Stay tuned!")

    def publish_version(
        self,
        context: RequestContext,
        function_name: FunctionName,
        code_sha256: String = None,  # TODO
        description: Description = None,  # TODO
        revision_id: String = None,
    ) -> FunctionConfiguration:
        state = LambdaServiceBackend.get()
        fn = state.functions[function_name]
        with fn.lock:
            if revision_id and revision_id != fn.latest.config.get("RevisionId"):
                raise PreconditionFailedException()  # TODO: test
            new_version = self._publish_version(fn=fn, description=description)
            return new_version.config

    def _publish_version(self, fn: LambdaFunction, description: str) -> LambdaFunctionVersion:
        version_qualifier = str(fn.next_version)

        # TODO: only publish a new version when code or config has actually changed
        # TODO: does change mean between last *published* version or anything in between?
        new_config: FunctionConfiguration = fn.latest.config.copy()
        # TODO: test if this overwrites the description in the function config
        # fn.latest.config['Description'] = description
        new_config["Version"] = version_qualifier
        new_code = fn.latest.code.copy()
        new_version = LambdaFunctionVersion(config=new_config, code=new_code)
        fn.versions[version_qualifier] = new_version
        fn.next_version = fn.next_version + 1
        return new_version

    def create_alias(
        self,
        context: RequestContext,
        function_name: FunctionName,
        name: Alias,
        function_version: Version,
        description: Description = None,
        routing_config: AliasRoutingConfiguration = None,
    ) -> AliasConfiguration:
        state = LambdaServiceBackend.get(context.region)
        # TODO: check for existence & conflict (and write test to check if this would lead to an exception on AWS?)
        fn = state.functions[function_name]
        alias_config = AliasConfiguration(
            AliasArn=generate_lambda_arn(
                account_id=int(context.account_id),
                region=context.region,
                fn_name=function_name,
                qualifier=name,
            ),
            Name=name,
            Description=description or "",
            RevisionId=fn.latest.config["RevisionId"],
            FunctionVersion=function_version,
            RoutingConfig=routing_config,
        )
        fn.aliases[alias_config["Name"]] = alias_config
        return alias_config

    def delete_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> None:
        # TODO: error handling
        state = LambdaServiceBackend.get(context.region)
        del state.functions[function_name].aliases[name]

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
        state = LambdaServiceBackend.get(context.region)
        fn = state.functions[function_name]
        alias_config = AliasConfiguration(
            AliasArn="asdfasf",  # TODO : generate
            Name=name,
            Description=description or "",
            RevisionId=fn.latest.config["RevisionId"],
            FunctionVersion=function_version,
            RoutingConfig=routing_config,
        )
        fn.aliases[alias_config["Name"]] = alias_config
        return alias_config

    def list_aliases(
        self,
        context: RequestContext,
        function_name: FunctionName,
        function_version: Version = None,
        marker: String = None,
        max_items: MaxListItems = None,
    ) -> ListAliasesResponse:
        state = LambdaServiceBackend.get(context.region)
        fn = state.functions[function_name]
        return ListAliasesResponse(Aliases=[a for a in fn.aliases.values()])

    def get_function_configuration(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        qualifier: Qualifier = None,  # TODO
    ) -> FunctionConfiguration:
        state = LambdaServiceBackend.get(context.region)
        fn = state.functions[function_name]
        return fn.latest.config

    def get_alias(
        self, context: RequestContext, function_name: FunctionName, name: Alias
    ) -> AliasConfiguration:
        state = LambdaServiceBackend.get(context.region)
        fn = state.functions[function_name]
        return fn.aliases[name]
