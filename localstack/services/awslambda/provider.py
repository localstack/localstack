import dataclasses
import logging
import threading
import time
import uuid
from typing import Dict

import regex

from localstack.aws.api import RequestContext
from localstack.aws.api.awslambda import (
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
    Handler,
    ImageConfig,
    InvocationResponse,
    InvocationType,
    KMSKeyArn,
    LambdaApi,
    LayerList,
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
    String,
    Tags,
    Timeout,
    TracingConfig,
    TracingMode,
    VpcConfig,
)
from localstack.services.awslambda.invocation.lambda_service import FunctionVersion, LambdaService
from localstack.services.awslambda.invocation.lambda_util import qualified_lambda_arn
from localstack.services.generic_proxy import RegionBackend
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

# some regexes to use (not used atm)
function_arn_regex = regex.compile(
    r"arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_\.]+(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)
function_name_regex = regex.compile(
    r" (arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?(function:)?([a-zA-Z0-9-_\.]+)(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)  # also length 1-170 incl.
handler_regex = regex.compile(r"[^\s]+")
kms_key_arn_regex = regex.compile(r"(arn:(aws[a-zA-Z-]*)?:[a-z0-9-.]+:.*)|()")
role_regex = regex.compile(r"arn:(aws[a-zA-Z-]*)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+")
master_arn_regex = regex.compile(
    r"arn:(aws[a-zA-Z-]*)?:lambda:[a-z]{2}(-gov)?-[a-z]+-\d{1}:\d{12}:function:[a-zA-Z0-9-_]+(:(\$LATEST|[a-zA-Z0-9-_]+))?"
)
signing_job_arn_regex = regex.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)
signing_profile_version_arn_regex = regex.compile(
    r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:([a-z]{2}(-gov)?-[a-z]+-\d{1})?:(\d{12})?:(.*)"
)


@dataclasses.dataclass
class LambdaFunctionVersion:
    # TODO: would prefer to use frozen dataclasses here
    # TODO: how to handle revision IDs?  => Don't necessarily need to "track" old versions, but used to verify latest state
    config: FunctionConfiguration
    code: FunctionCode


@dataclasses.dataclass
class LambdaFunction:
    latest: LambdaFunctionVersion  # points to the '$LATEST' version
    versions: Dict[str, LambdaFunctionVersion] = dataclasses.field(default_factory=dict)
    aliases: Dict[str, str] = dataclasses.field(default_factory=dict)
    next_version: int = 1
    lock: threading.RLock = dataclasses.field(default_factory=threading.RLock)

    # TODO: implement later
    # provisioned_concurrency_configs: Dict[str, ProvisionedConcurrencyConfig]
    # code_signing_config: Dict[str, CodeSigningConfig]
    # function_event_invoke_config: Dict[str, EventInvokeConfig]
    # function_concurrency: Dict[str, FunctionConcurrency]


class LambdaServiceBackend(RegionBackend):
    # name => Function; Account/region are implicit through the Backend
    functions: Dict[str, LambdaFunction] = {}
    # static tagging service instance
    TAGS = TaggingService()


class LambdaProvider(LambdaApi, ServiceLifecycleHook):

    lambda_service: LambdaService
    lock: threading.RLock

    def __init__(self) -> None:
        self.lambda_service = LambdaService()
        self.lock = threading.RLock()

    def on_before_stop(self):
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

        if package_type == PackageType.Image and code.get("ImageUri") and ImageConfig:
            # container image
            # image_config
            raise ServiceException("PRO feature")  # TODO implement PRO
        else:
            # package_type
            # runtime
            # handler
            # layers
            # managed runtime or provided runtime
            if runtime in [Runtime.provided, Runtime.provided_al2]:
                # provided runtime
                raise ServiceException("Not implemented")  # TODO
                pass
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
            Description=description or "Lambda ASF baby!",  # for now we'll just use this
            RevisionId=str(uuid.uuid4()),
            MemorySize=memory_size,
            Timeout=timeout,
            CodeSize=5,  # TODO
            CodeSha256="asdf",  # TODO
            Version="$LATEST",
            TracingConfig=TracingConfig(Mode=TracingMode.PassThrough),  # TODO
            PackageType=package_type,
            Architectures=architectures,
            # TODO: implement proper status tracking
            # LastModified=,
            # LastUpdateStatus=,
            # LastUpdateStatusReasonCode=,
            # LastUpdateStatusReason=,
            # StateReason=,
            # StateReasonCode=,
            # State=,
        )

        # "State": "Pending",
        # "StateReason": "The funcation is being created.",
        # "StateReasonCode": "Creating",

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

    def list_functions(
        self,
        context: RequestContext,
        master_region: MasterRegion = None,  # TODO (only relevant vo
        function_version: FunctionVersion = None,  # TODO
        marker: String = None,  # TODO
        max_items: MaxListItems = None,  # TODO
    ) -> ListFunctionsResponse:
        # TODO: limit fields returned
        # TODO: implement paging
        state = LambdaServiceBackend.get()
        return ListFunctionsResponse(Functions=[f.latest.config for f in state.functions.values()])

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
            log_type=log_type,
            client_context=client_context,
            payload=payload,
        )
        result = result.result()
        LOG.debug("Lambda invocation duration: %0.2fms", (time.perf_counter() - time_before) * 1000)
        LOG.debug("Result: %s", result)
        return InvocationResponse(StatusCode=200, Payload=result.payload)

    # TODO: does deleting the latest published version affect the next versions number?
    def delete_function(
        self,
        context: RequestContext,
        function_name: FunctionName,
        qualifier: Qualifier = None,
    ) -> None:
        state = LambdaServiceBackend.get()
        if qualifier and qualifier != "$LATEST":
            # only delete this version
            pass  # TODO
        else:
            # TODO: this actually first needs to set the state and handle this in the lambda service and all downstream services!
            # TODO: delete all related resources (Aliases, Versions)
            del state.functions[function_name]

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
        if fn.latest.config["RevisionId"] != revision_id:
            raise PreconditionFailedException()  # TODO: test

        with fn.lock:
            if fn.latest.config["RevisionId"] != revision_id:
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
