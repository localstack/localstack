import base64
import concurrent.futures
import dataclasses
import io
import logging
import random
import uuid
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Dict, Optional

from localstack import config
from localstack.aws.api.lambda_ import (
    InvalidParameterValueException,
    InvocationType,
    LastUpdateStatus,
    ResourceConflictException,
    ResourceNotFoundException,
    State,
)
from localstack.services.awslambda.api_utils import (
    lambda_arn,
    qualified_lambda_arn,
    qualifier_is_alias,
)
from localstack.services.awslambda.invocation.lambda_models import (
    LAMBDA_LIMITS_CODE_SIZE_UNZIPPED_DEFAULT,
    ArchiveCode,
    Function,
    FunctionVersion,
    HotReloadingCode,
    ImageCode,
    Invocation,
    InvocationResult,
    S3Code,
    UpdateStatus,
    VersionState,
)
from localstack.services.awslambda.invocation.models import lambda_stores
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.utils.archives import get_unzipped_size, is_zip_file
from localstack.utils.aws import aws_stack
from localstack.utils.container_utils.container_client import ContainerException
from localstack.utils.docker_utils import DOCKER_CLIENT as CONTAINER_CLIENT
from localstack.utils.strings import to_str

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT_SECONDS = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128


class LambdaService:
    # mapping from qualified ARN to version manager
    lambda_running_versions: Dict[str, LambdaVersionManager]
    lambda_starting_versions: Dict[str, LambdaVersionManager]
    lambda_version_manager_lock: RLock
    task_executor: Executor

    def __init__(self) -> None:
        self.lambda_running_versions = {}
        self.lambda_starting_versions = {}
        self.lambda_version_manager_lock = RLock()
        self.task_executor = ThreadPoolExecutor()

    def stop(self) -> None:
        """
        Stop the whole lambda service
        """
        shutdown_futures = []
        for version_manager in self.lambda_running_versions.values():
            shutdown_futures.append(self.task_executor.submit(version_manager.stop))
        for version_manager in self.lambda_starting_versions.values():
            shutdown_futures.append(self.task_executor.submit(version_manager.stop))
            shutdown_futures.append(
                self.task_executor.submit(
                    version_manager.function_version.config.code.destroy_cached
                )
            )
        concurrent.futures.wait(shutdown_futures, timeout=5)
        self.task_executor.shutdown(cancel_futures=True)

    def stop_version(self, qualified_arn: str) -> None:
        """
        Stops a specific lambda service version
        :param qualified_arn: Qualified arn for the version to stop
        """
        LOG.debug("Stopping version %s", qualified_arn)
        version_manager = self.lambda_running_versions.pop(
            qualified_arn, self.lambda_starting_versions.pop(qualified_arn, None)
        )
        if not version_manager:
            raise ValueError(f"Unable to find version manager for {qualified_arn}")
        self.task_executor.submit(version_manager.stop)

    def get_lambda_version_manager(self, function_arn: str) -> LambdaVersionManager:
        """
        Get the lambda version for the given arn
        :param function_arn: qualified arn for the lambda version
        :return: LambdaVersionManager for the arn
        """
        version_manager = self.lambda_running_versions.get(function_arn)
        if not version_manager:
            raise ValueError(f"Could not find version '{function_arn}'. Is it created?")

        return version_manager

    def create_function_version(self, function_version: FunctionVersion) -> None:
        """
        Creates a new function version (manager), and puts it in the startup dict

        :param function_version: Function Version to create
        """
        with self.lambda_version_manager_lock:
            qualified_arn = function_version.id.qualified_arn()
            version_manager = self.lambda_starting_versions.get(qualified_arn)
            if version_manager:
                raise Exception(
                    "Version '%s' already starting up and in state %s",
                    qualified_arn,
                    version_manager.state,
                )
            version_manager = LambdaVersionManager(
                function_arn=qualified_arn, function_version=function_version, lambda_service=self
            )
            self.lambda_starting_versions[qualified_arn] = version_manager
        self.task_executor.submit(version_manager.start)

    def publish_version(self, function_version: FunctionVersion):
        """
        Synchronously create a function version (manager)
        Should only be called on publishing new versions, which basically clone an existing one.
        The new version needs to be added to the lambda store before invoking this.
        After successful completion of this method, the lambda version stored will be modified to be active, with a new revision id.
        It will then be active for execution, and should be retrieved again from the store before returning the data over the API.

        :param function_version: Function Version to create
        """
        with self.lambda_version_manager_lock:
            qualified_arn = function_version.id.qualified_arn()
            version_manager = self.lambda_starting_versions.get(qualified_arn)
            if version_manager:
                raise Exception(
                    "Version '%s' already starting up and in state %s",
                    qualified_arn,
                    version_manager.state,
                )
            version_manager = LambdaVersionManager(
                function_arn=qualified_arn, function_version=function_version, lambda_service=self
            )
            self.lambda_starting_versions[qualified_arn] = version_manager
        version_manager.start()

    # Commands
    def invoke(
        self,
        function_name: str,
        qualifier: str,
        region: str,
        account_id: str,
        invocation_type: InvocationType | None,
        client_context: Optional[str],
        payload: bytes | None,
    ) -> Future[InvocationResult] | None:
        """
        Invokes a specific version of a lambda

        :param function_name: Function name
        :param qualifier: Function version qualifier
        :param region: Region of the function
        :param account_id: Account id of the function
        :param invocation_type: Invocation Type
        :param client_context: Client Context, if applicable
        :param payload: Invocation payload
        :return: A future for the invocation result
        """
        # Invoked arn (for lambda context) does not have qualifier if not supplied
        invoked_arn = lambda_arn(
            function_name=function_name,
            qualifier=qualifier,
            account=account_id,
            region=region,
        )
        qualifier = qualifier or "$LATEST"
        state = lambda_stores[account_id][region]
        function = state.functions.get(function_name)

        if function is None:
            raise ResourceNotFoundException(
                f"Function not found: {invoked_arn}", Type="User"
            )  # TODO: test

        if qualifier_is_alias(qualifier):
            alias = function.aliases.get(qualifier)
            if not alias:
                raise ResourceNotFoundException(f"Function not found: {invoked_arn}", Type="User")
            version_qualifier = alias.function_version
            if alias.routing_configuration:
                version, probability = next(
                    iter(alias.routing_configuration.version_weights.items())
                )
                if random.random() < probability:
                    version_qualifier = version
        else:
            version_qualifier = qualifier

        # Need the qualified arn to exactly get the target lambda
        qualified_arn = qualified_lambda_arn(function_name, version_qualifier, account_id, region)
        try:
            version_manager = self.get_lambda_version_manager(qualified_arn)
        except ValueError:
            version = function.versions.get(version_qualifier)
            state = version and version.config.state.state
            raise ResourceConflictException(
                f"The operation cannot be performed at this time. The function is currently in the following state: {state}"
            )
        # empty payloads have to work as well
        if payload is None:
            payload = b"{}"
        if invocation_type is None:
            invocation_type = "RequestResponse"
        # TODO payload verification  An error occurred (InvalidRequestContentException) when calling the Invoke operation: Could not parse request body into json: Could not parse payload into json: Unexpected character (''' (code 39)): expected a valid value (JSON String, Number, Array, Object or token 'null', 'true' or 'false')
        #  at [Source: (byte[])"'test'"; line: 1, column: 2]

        return version_manager.invoke(
            invocation=Invocation(
                payload=payload,
                invoked_arn=invoked_arn,
                client_context=client_context,
                invocation_type=invocation_type,
            )
        )

    def update_version(self, new_version: FunctionVersion) -> None:
        """
        Updates a given version. Will perform a rollover, so the old version will be active until the new one is ready
        to be invoked

        :param new_version: New version (with the same qualifier as an older one)
        """
        if new_version.qualified_arn not in self.lambda_running_versions:
            raise ValueError(
                f"Version {new_version.qualified_arn} cannot be updated if an old one is not running"
            )

        return self.create_function_version(function_version=new_version)

    def update_version_state(
        self, function_version: FunctionVersion, new_state: VersionState
    ) -> None:
        """
        Update the version state for the given function version.

        This will perform a rollover to the given function if the new state is active and there is a previously
        running version registered. The old version will be shutdown and its code deleted.

        If the new state is failed, it will abort the update and mark it as failed.
        If an older version is still running, it will keep running.

        :param function_version: Version reporting the state
        :param new_state: New state
        """
        function_arn = function_version.qualified_arn
        old_version = None
        with self.lambda_version_manager_lock:
            new_version = self.lambda_starting_versions.pop(function_arn)
            if not new_version:
                raise ValueError(
                    f"Version {function_arn} reporting state {new_state.state} does exist in the starting versions."
                )
            if new_state.state == State.Active:
                old_version = self.lambda_running_versions.get(function_arn, None)
                self.lambda_running_versions[function_arn] = new_version
                update_status = UpdateStatus(status=LastUpdateStatus.Successful)
            elif new_state.state == State.Failed:
                update_status = UpdateStatus(status=LastUpdateStatus.Failed)
                self.task_executor.submit(new_version.stop)
            else:
                # TODO what to do if state pending or inactive is supported?
                self.task_executor.submit(new_version.stop)
                LOG.error(
                    "State %s for version %s should not have been reported. New version will be stopped.",
                    new_state,
                    function_arn,
                )
                return

        # TODO is it necessary to get the version again? Should be locked for modification anyway
        state = lambda_stores[function_version.id.account][function_version.id.region]
        function = state.functions[function_version.id.function_name]
        current_version = function.versions[function_version.id.qualifier]
        new_version = dataclasses.replace(
            current_version,
            config=dataclasses.replace(
                current_version.config, state=new_state, last_update=update_status
            ),
        )
        state.functions[function_version.id.function_name].versions[
            function_version.id.qualifier
        ] = new_version

        if old_version:
            # if there is an old version, we assume it is an update, and stop the old one
            self.task_executor.submit(old_version.stop)
            self.task_executor.submit(
                destroy_code_if_not_used, old_version.function_version.config.code, function
            )


def is_code_used(code: S3Code, function: Function) -> bool:
    """
    Check if given code is still used in some version of the function

    :param code: Code object
    :param function: function to check
    :return: bool whether code is used in another version of the function
    """
    with function.lock:
        return any(code == version.config.code for version in function.versions.values())


def destroy_code_if_not_used(code: S3Code, function: Function) -> None:
    """
    Destroy the given code if it is not used in some version of the function
    Do nothing otherwise

    :param code: Code object
    :param function: Function the code belongs too
    """
    with function.lock:
        if not is_code_used(code, function):
            code.destroy()


def store_lambda_archive(
    archive_file: bytes, function_name: str, region_name: str, account_id: str
) -> S3Code:
    """
    Stores the given lambda archive in an internal s3 bucket.
    Also checks if zipfile matches the specifications

    :param archive_file: Archive file to store
    :param function_name: function name the archive should be stored for
    :param region_name: region name the archive should be stored for
    :param account_id: account id the archive should be stored for
    :return: S3 Code object representing the archive stored in S3
    """
    # check if zip file
    if not is_zip_file(archive_file):
        raise InvalidParameterValueException(
            "Could not unzip uploaded file. Please check your file, then try to upload again.",
            Type="User",
        )
    # check unzipped size
    unzipped_size = get_unzipped_size(zip_file=io.BytesIO(archive_file))
    if unzipped_size >= LAMBDA_LIMITS_CODE_SIZE_UNZIPPED_DEFAULT:
        raise InvalidParameterValueException(
            f"Unzipped size must be smaller than {LAMBDA_LIMITS_CODE_SIZE_UNZIPPED_DEFAULT} bytes",
            Type="User",
        )
    # store all buckets in us-east-1 for now
    s3_client: "S3Client" = aws_stack.connect_to_service("s3", region_name="us-east-1")
    bucket_name = f"awslambda-{region_name}-tasks"
    # s3 create bucket is idempotent
    s3_client.create_bucket(Bucket=bucket_name)
    code_id = f"{function_name}-{uuid.uuid4()}"
    key = f"snapshots/{account_id}/{code_id}"
    s3_client.upload_fileobj(Fileobj=io.BytesIO(archive_file), Bucket=bucket_name, Key=key)
    code_sha256 = to_str(base64.b64encode(sha256(archive_file).digest()))
    return S3Code(
        id=code_id,
        s3_bucket=bucket_name,
        s3_key=key,
        s3_object_version=None,
        code_sha256=code_sha256,
        code_size=len(archive_file),
    )


def create_hot_reloading_code(path: str) -> HotReloadingCode:
    # TODO extract into other function
    if not Path(path).is_absolute():
        raise InvalidParameterValueException(
            "When using hot reloading, the archive key has to be an absolute path! Your archive key: %s",
            path,
        )
    # TODO fix types
    return HotReloadingCode(host_path=path)


def store_s3_bucket_archive(
    archive_bucket: str,
    archive_key: str,
    archive_version: Optional[str],
    function_name: str,
    region_name: str,
    account_id: str,
) -> ArchiveCode:
    """
    Takes the lambda archive stored in the given bucket and stores it in an internal s3 bucket

    :param archive_bucket: Bucket the archive is stored in
    :param archive_key: Key the archive is stored under
    :param archive_version: Version of the archive object in the bucket
    :param function_name: function name the archive should be stored for
    :param region_name: region name the archive should be stored for
    :param account_id: account id the archive should be stored for
    :return: S3 Code object representing the archive stored in S3
    """
    # TODO change test-bucket-for-hot-reloading to actual bucket
    if archive_bucket == config.BUCKET_MARKER_LOCAL:
        return create_hot_reloading_code(path=archive_key)
    s3_client: "S3Client" = aws_stack.connect_to_service("s3")
    kwargs = {"VersionId": archive_version} if archive_version else {}
    archive_file = s3_client.get_object(Bucket=archive_bucket, Key=archive_key, **kwargs)[
        "Body"
    ].read()
    return store_lambda_archive(
        archive_file, function_name=function_name, region_name=region_name, account_id=account_id
    )


def create_image_code(image_uri: str) -> ImageCode:
    """
    Creates an image code by inspecting the provided image

    :param image_uri: Image URI of the image to inspect
    :return: Image code object
    """
    code_sha256 = "<cannot-find-image>"
    try:
        CONTAINER_CLIENT.pull_image(docker_image=image_uri)
    except ContainerException:
        LOG.debug("Cannot pull image %s. Maybe only available locally?", image_uri)
    try:
        code_sha256 = CONTAINER_CLIENT.inspect_image(image_name=image_uri)["RepoDigests"][
            0
        ].rpartition(":")[2]
    except Exception as e:
        LOG.debug(
            "Cannot inspect image %s. Is this image and/or docker available: %s", image_uri, e
        )
    return ImageCode(image_uri=image_uri, code_sha256=code_sha256, repository_type="ECR")
