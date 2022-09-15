import base64
import concurrent.futures
import io
import logging
import uuid
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from hashlib import sha256
from threading import RLock
from typing import Dict, List, Optional

from mypy_boto3_s3 import S3Client

from localstack.aws.api.lambda_ import InvocationType, ResourceNotFoundException
from localstack.services.awslambda.invocation.lambda_models import (
    FunctionVersion,
    Invocation,
    InvocationResult,
    S3Code,
)
from localstack.services.awslambda.invocation.models import lambda_stores
from localstack.services.awslambda.invocation.version_manager import LambdaVersionManager
from localstack.utils.aws import aws_stack
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)

LAMBDA_DEFAULT_TIMEOUT_SECONDS = 3
LAMBDA_DEFAULT_MEMORY_SIZE = 128


class LambdaService:
    # mapping from qualified ARN to version manager
    lambda_version_managers: Dict[str, LambdaVersionManager]
    lambda_version_manager_lock: RLock
    task_executor: Executor

    def __init__(self) -> None:
        self.lambda_version_managers = {}
        self.lambda_version_manager_lock = RLock()
        self.task_executor = ThreadPoolExecutor()

    def stop(self) -> None:
        shutdown_futures = []
        for version_manager in self.lambda_version_managers.values():
            shutdown_futures.append(self.task_executor.submit(version_manager.stop))
        concurrent.futures.wait(shutdown_futures, timeout=5)
        self.task_executor.shutdown(cancel_futures=True)

    def stop_version(self, qualified_arn: str) -> None:
        """
        Stops a specific lambda service version
        :param qualified_arn: Qualified arn for the version to stop
        """
        LOG.debug("Stopping version %s", qualified_arn)
        version_manager = self.lambda_version_managers.pop(qualified_arn)
        if not version_manager:
            raise ValueError(f"Unable to find version manager for {qualified_arn}")
        self.task_executor.submit(version_manager.stop)

    def get_lambda_version_manager(self, function_arn: str) -> LambdaVersionManager:
        """
        Get the lambda version for the given arn
        :param function_arn: qualified arn for the lambda version
        :return: LambdaVersionManager for the arn
        """
        version_manager = self.lambda_version_managers.get(function_arn)
        if not version_manager:
            raise ValueError(f"Could not find version '{function_arn}'. Is it created?")

        return version_manager

    # TODO: is this sync?
    # TODO: what's the point of the qualifier here?
    def delete_function(
        self, account_id: str, region_name: str, function_name: str, qualifier: str
    ):
        state = lambda_stores[account_id][region_name]
        if function_name not in state.functions:
            raise ResourceNotFoundException(f"Function not found: {function_name}")
        function = state.functions.pop(function_name)
        for version in function.versions.values():
            self.stop_version(qualified_arn=version.id.qualified_arn())

    def delete_version(self, function_version: FunctionVersion):
        # TODO is this necessary?
        self.stop_version(qualified_arn=function_version.id.qualified_arn())

    def get_function_version(
        self,
        account_id: str,
        region_name: str,
        function_name: str,
        qualifier: Optional[str] = "$LATEST",
    ) -> FunctionVersion:
        state = lambda_stores[account_id][region_name]
        return state.functions[function_name].versions[qualifier]

    def list_function_versions(self, account_id: str, region_name: str) -> List[FunctionVersion]:
        state = lambda_stores[account_id][region_name]
        return [f.latest() for f in state.functions.values()]  # TODO: qualifier

    def create_function_version(self, function_version: FunctionVersion) -> None:
        with self.lambda_version_manager_lock:
            qualified_arn = function_version.id.qualified_arn()
            version_manager = self.lambda_version_managers.get(qualified_arn)
            if version_manager:
                raise Exception("Version '%s' already created", qualified_arn)
            version_manager = LambdaVersionManager(
                function_arn=qualified_arn,
                function_version=function_version,
            )
            self.lambda_version_managers[qualified_arn] = version_manager
            self.task_executor.submit(version_manager.start)

    # Commands
    def invoke(
        self,
        function_arn_qualified: str,
        invocation_type: InvocationType,
        client_context: Optional[str],
        payload: bytes,
    ) -> "Future[InvocationResult]":
        version_manager = self.get_lambda_version_manager(function_arn_qualified)
        return version_manager.invoke(
            invocation=Invocation(
                payload=payload, client_context=client_context, invocation_type=invocation_type
            )
        )


def store_lambda_archive(
    archive_file: bytes, function_name: str, region_name: str, account_id: str
) -> S3Code:
    # store all buckets in us-east-1 for now
    s3_client: "S3Client" = aws_stack.connect_to_service("s3", region_name="us-east-1")
    bucket_name = f"awslambda-{region_name}-tasks"
    # s3 create bucket is idempotent
    s3_client.create_bucket(Bucket=bucket_name)
    key = f"snapshots/{account_id}/{function_name}-{uuid.uuid4()}"
    s3_client.upload_fileobj(Fileobj=io.BytesIO(archive_file), Bucket=bucket_name, Key=key)
    code_sha256 = to_str(base64.b64encode(sha256(archive_file).digest()))
    return S3Code(
        s3_bucket=bucket_name,
        s3_key=key,
        s3_object_version=None,
        code_sha256=code_sha256,
        code_size=len(archive_file),
    )


def store_s3_bucket_archive(
    archive_bucket: str,
    archive_key: str,
    archive_version: Optional[str],
    function_name: str,
    region_name: str,
    account_id: str,
) -> S3Code:
    s3_client: "S3Client" = aws_stack.connect_to_service("s3")
    kwargs = {"VersionId": archive_version} if archive_version else {}
    archive_file = s3_client.get_object(Bucket=archive_bucket, Key=archive_key, **kwargs)[
        "Body"
    ].read()
    return store_lambda_archive(
        archive_file, function_name=function_name, region_name=region_name, account_id=account_id
    )
