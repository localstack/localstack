import base64
import contextlib
import dataclasses
import glob
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from multiprocessing import Process, Queue
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.config import LAMBDA_TRUNCATE_STDOUT, TMP_FOLDER
from localstack.constants import DEFAULT_LAMBDA_CONTAINER_REGISTRY
from localstack.runtime.hooks import hook_spec
from localstack.services.awslambda.lambda_utils import (
    API_PATH_ROOT,
    LAMBDA_RUNTIME_PROVIDED,
    get_container_network_for_lambda,
    get_main_endpoint_from_container,
    get_record_from_event,
    is_java_lambda,
    is_nodejs_runtime,
    rm_docker_container,
    store_lambda_logs,
)
from localstack.services.install import GO_LAMBDA_RUNTIME, INSTALL_PATH_LOCALSTACK_FAT_JAR
from localstack.utils import bootstrap
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.aws.dead_letter_queue import (
    lambda_error_to_dead_letter_queue,
    sqs_error_to_dead_letter_queue,
)
from localstack.utils.cloudwatch.cloudwatch_util import cloudwatched
from localstack.utils.common import (
    TMP_FILES,
    CaptureOutput,
    get_all_subclasses,
    get_free_tcp_port,
    in_docker,
    is_port_open,
    json_safe,
    last_index_of,
    long_uid,
    md5,
    now,
    retry,
    run,
    run_safe,
    safe_requests,
    save_file,
    short_uid,
    timestamp,
    to_bytes,
    to_str,
    truncate,
    wait_for_port_open,
)
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    ContainerException,
    DockerContainerStatus,
    PortMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.run import FuncThread

# constants
LAMBDA_EXECUTOR_JAR = INSTALL_PATH_LOCALSTACK_FAT_JAR
LAMBDA_EXECUTOR_CLASS = "cloud.localstack.LambdaExecutor"
LAMBDA_HANDLER_ENV_VAR_NAME = "_HANDLER"
EVENT_FILE_PATTERN = "%s/lambda.event.*.json" % config.dirs.tmp

LAMBDA_SERVER_UNIQUE_PORTS = 500
LAMBDA_SERVER_PORT_OFFSET = 5000

LAMBDA_API_UNIQUE_PORTS = 500
LAMBDA_API_PORT_OFFSET = 9000

MAX_ENV_ARGS_LENGTH = 20000

# port number used in lambci images for stay-open invocation mode
STAY_OPEN_API_PORT = 9001

INTERNAL_LOG_PREFIX = "ls-daemon: "

# logger
LOG = logging.getLogger(__name__)

# maximum time a pre-allocated container can sit idle before getting killed
MAX_CONTAINER_IDLE_TIME_MS = 600 * 1000

# SQS event source name
EVENT_SOURCE_SQS = "aws:sqs"

# maps lambda arns to concurrency locks
LAMBDA_CONCURRENCY_LOCK = {}

# CWD folder of handler code in Lambda containers
DOCKER_TASK_FOLDER = "/var/task"

# Lambda event type
LambdaEvent = Union[Dict[str, Any], str, bytes]

# Hook definitions
HOOKS_ON_LAMBDA_DOCKER_SEPARATE_EXECUTION = "localstack.hooks.on_docker_separate_execution"
HOOKS_ON_LAMBDA_DOCKER_REUSE_CONTAINER_CREATION = (
    "localstack.hooks.on_docker_reuse_container_creation"
)

on_docker_separate_execution = hook_spec(HOOKS_ON_LAMBDA_DOCKER_SEPARATE_EXECUTION)
on_docker_reuse_container_creation = hook_spec(HOOKS_ON_LAMBDA_DOCKER_REUSE_CONTAINER_CREATION)


class InvocationException(Exception):
    def __init__(self, message, log_output=None, result=None):
        super(InvocationException, self).__init__(message)
        self.log_output = log_output
        self.result = result


class LambdaContext(object):
    DEFAULT_MEMORY_LIMIT = 1536

    def __init__(
        self, lambda_function: LambdaFunction, qualifier: str = None, context: Dict[str, Any] = None
    ):
        context = context or {}
        self.function_name = lambda_function.name()
        self.function_version = lambda_function.get_qualifier_version(qualifier)
        self.client_context = context.get("client_context")
        self.invoked_function_arn = lambda_function.arn()
        if qualifier:
            self.invoked_function_arn += ":" + qualifier
        self.cognito_identity = context.get("identity")
        self.aws_request_id = str(uuid.uuid4())
        self.memory_limit_in_mb = lambda_function.memory_size or self.DEFAULT_MEMORY_LIMIT
        self.log_group_name = "/aws/lambda/%s" % self.function_name
        self.log_stream_name = "%s/[1]%s" % (timestamp(format="%Y/%m/%d"), short_uid())

    def get_remaining_time_in_millis(self):
        # TODO implement!
        return 1000 * 60


class AdditionalInvocationOptions:
    # Maps file keys to file paths. The keys can be used as placeholders in the env. variables
    #  and command args to reference files - e.g., given `files_to_add` as {"f1": "/local/path"} and
    #  `env_updates` as {"MYENV": "{f1}"}, the Lambda handler will receive an environment variable
    #  `MYENV=/lambda/path` and the file /lambda/path will be accessible to the Lambda handler
    #  (either locally, or inside Docker).
    files_to_add: Dict[str, str]
    # Environment variable updates to apply for the invocation
    env_updates: Dict[str, str]
    # Updated command to use for starting the Lambda process (or None)
    updated_command: Optional[str]
    # Updated handler as entry point of Lambda function (or None)
    updated_handler: Optional[str]

    def __init__(
        self,
        files_to_add=None,
        env_updates=None,
        updated_command=None,
        updated_handler=None,
    ):
        self.files_to_add = files_to_add or {}
        self.env_updates = env_updates or {}
        self.updated_command = updated_command
        self.updated_handler = updated_handler


class InvocationResult:
    def __init__(self, result, log_output=""):
        if isinstance(result, InvocationResult):
            raise Exception("Unexpected invocation result type: %s" % result)
        self.result = result
        self.log_output = log_output or ""


class InvocationContext:
    lambda_function: LambdaFunction
    function_version: str
    handler: str
    event: LambdaEvent
    lambda_command: Union[str, List[str]]  # TODO: change to List[str] ?
    docker_flags: Union[str, List[str]]  # TODO: change to List[str] ?
    environment: Dict[str, Optional[str]]
    context: LambdaContext
    invocation_type: str  # "Event" or "RequestResponse"

    def __init__(
        self,
        lambda_function: LambdaFunction,
        event: LambdaEvent,
        environment=None,
        context=None,
        lambda_command=None,
        docker_flags=None,
        function_version=None,
        invocation_type=None,
    ):
        self.lambda_function = lambda_function
        self.handler = lambda_function.handler
        self.event = event
        self.environment = {} if environment is None else environment
        self.context = {} if context is None else context
        self.lambda_command = lambda_command
        self.docker_flags = docker_flags
        self.function_version = function_version
        self.invocation_type = invocation_type


class LambdaExecutorPlugin:
    """Plugin abstraction that allows to hook in additional functionality into the Lambda executors."""

    INSTANCES: List["LambdaExecutorPlugin"] = []

    def initialize(self):
        """Called once, for any active plugin to run initialization logic (e.g., downloading dependencies).
        Uses lazy initialization - i.e., runs only after the first should_apply() call returns True"""
        pass

    def should_apply(self, context: InvocationContext) -> bool:
        """Whether the plugin logic should get applied for the given Lambda invocation context."""
        return False

    def prepare_invocation(
        self, context: InvocationContext
    ) -> Optional[Union[AdditionalInvocationOptions, InvocationResult]]:
        """Return additional invocation options for given Lambda invocation context. Optionally, an
        InvocationResult can be returned, in which case the result is returned to the client right away."""
        return None

    def process_result(
        self, context: InvocationContext, result: InvocationResult
    ) -> InvocationResult:
        """Optionally modify the result returned from the given Lambda invocation."""
        return result

    def init_function_configuration(self, lambda_function: LambdaFunction):
        """Initialize the configuration of the given function upon creation or function update."""
        pass

    def init_function_code(self, lambda_function: LambdaFunction):
        """Initialize the code of the given function upon creation or function update."""
        pass

    @classmethod
    def get_plugins(cls) -> List["LambdaExecutorPlugin"]:
        if not cls.INSTANCES:
            classes = get_all_subclasses(LambdaExecutorPlugin)
            cls.INSTANCES = [clazz() for clazz in classes]
        return cls.INSTANCES


class LambdaInvocationForwarderPlugin(LambdaExecutorPlugin):
    """Plugin that forwards Lambda invocations to external targets defined in LAMBDA_FORWARD_URL"""

    def should_apply(self, context: InvocationContext) -> bool:
        """If LAMBDA_FORWARD_URL is configured, forward the invocation of this Lambda to the target URL."""
        func_forward_url = self._forward_url(context)
        return bool(func_forward_url)

    def prepare_invocation(
        self, context: InvocationContext
    ) -> Optional[Union[AdditionalInvocationOptions, InvocationResult]]:
        forward_url = self._forward_url(context)
        result = self._forward_to_url(
            forward_url,
            context.lambda_function,
            context.event,
            context.context,
            context.invocation_type,
        )
        return result

    def _forward_to_url(
        self,
        forward_url: str,
        lambda_function: LambdaFunction,
        event: Union[Dict, bytes],
        context: LambdaContext,
        invocation_type: str,
    ) -> InvocationResult:
        func_name = lambda_function.name()
        url = "%s%s/functions/%s/invocations" % (forward_url, API_PATH_ROOT, func_name)

        copied_env_vars = lambda_function.envvars.copy()
        copied_env_vars["LOCALSTACK_HOSTNAME"] = config.HOSTNAME_EXTERNAL
        copied_env_vars["LOCALSTACK_EDGE_PORT"] = str(config.EDGE_PORT)

        headers = aws_stack.mock_aws_request_headers("lambda")
        headers["X-Amz-Region"] = lambda_function.region()
        headers["X-Amz-Request-Id"] = context.aws_request_id
        headers["X-Amz-Handler"] = lambda_function.handler
        headers["X-Amz-Function-ARN"] = context.invoked_function_arn
        headers["X-Amz-Function-Name"] = context.function_name
        headers["X-Amz-Function-Version"] = context.function_version
        headers["X-Amz-Role"] = lambda_function.role
        headers["X-Amz-Runtime"] = lambda_function.runtime
        headers["X-Amz-Timeout"] = str(lambda_function.timeout)
        headers["X-Amz-Memory-Size"] = str(context.memory_limit_in_mb)
        headers["X-Amz-Log-Group-Name"] = context.log_group_name
        headers["X-Amz-Log-Stream-Name"] = context.log_stream_name
        headers["X-Amz-Env-Vars"] = json.dumps(copied_env_vars)
        headers["X-Amz-Last-Modified"] = str(int(lambda_function.last_modified.timestamp() * 1000))
        headers["X-Amz-Invocation-Type"] = invocation_type
        headers["X-Amz-Log-Type"] = "Tail"
        if context.client_context:
            headers["X-Amz-Client-Context"] = context.client_context
        if context.cognito_identity:
            headers["X-Amz-Cognito-Identity"] = context.cognito_identity

        data = run_safe(lambda: to_str(event)) or event
        data = json.dumps(json_safe(data)) if isinstance(data, dict) else str(data)
        LOG.debug(
            "Forwarding Lambda invocation to LAMBDA_FORWARD_URL: %s", config.LAMBDA_FORWARD_URL
        )
        result = safe_requests.post(url, data, headers=headers)
        if result.status_code >= 400:
            raise Exception(
                "Received error status code %s from external Lambda invocation" % result.status_code
            )
        content = run_safe(lambda: to_str(result.content)) or result.content
        LOG.debug(
            "Received result from external Lambda endpoint (status %s): %s",
            result.status_code,
            content,
        )
        result = InvocationResult(content)
        return result

    def _forward_url(self, context: InvocationContext) -> str:
        env_vars = context.lambda_function.envvars
        return env_vars.get("LOCALSTACK_LAMBDA_FORWARD_URL") or config.LAMBDA_FORWARD_URL


def handle_error(
    lambda_function: LambdaFunction, event: Dict, error: Exception, asynchronous: bool = False
):
    if asynchronous:
        if get_record_from_event(event, "eventSource") == EVENT_SOURCE_SQS:
            sqs_queue_arn = get_record_from_event(event, "eventSourceARN")
            if sqs_queue_arn:
                # event source is SQS, send event back to dead letter queue
                return sqs_error_to_dead_letter_queue(sqs_queue_arn, event, error)
        else:
            # event source is not SQS, send back to lambda dead letter queue
            lambda_error_to_dead_letter_queue(lambda_function, event, error)


class LambdaAsyncLocks:
    locks: Dict[str, Union[threading.Semaphore, threading.Lock]]
    creation_lock: threading.Lock

    def __init__(self):
        self.locks = {}
        self.creation_lock = threading.Lock()

    def assure_lock_present(
        self, key: str, lock: Union[threading.Semaphore, threading.Lock]
    ) -> Union[threading.Semaphore, threading.Lock]:
        with self.creation_lock:
            return self.locks.setdefault(key, lock)


LAMBDA_ASYNC_LOCKS = LambdaAsyncLocks()


class LambdaExecutor(object):
    """Base class for Lambda executors. Subclasses must overwrite the _execute method"""

    def __init__(self):
        # keeps track of each function arn and the last time it was invoked
        self.function_invoke_times = {}

    def _prepare_environment(self, lambda_function: LambdaFunction):
        # setup environment pre-defined variables for docker environment
        result = lambda_function.envvars.copy()

        # injecting aws credentials into docker environment if not provided
        aws_stack.inject_test_credentials_into_env(result)
        # injecting the region into the docker environment
        aws_stack.inject_region_into_env(result, lambda_function.region())

        return result

    def execute(
        self,
        func_arn: str,  # TODO remove and get from lambda_function
        lambda_function: LambdaFunction,
        event: Dict,
        context: LambdaContext = None,
        version: str = None,
        asynchronous: bool = False,
        callback: Callable = None,
        lock_discriminator: str = None,
    ):
        # note: leave here to avoid circular import issues
        from localstack.utils.aws.message_forwarding import lambda_result_to_destination

        def do_execute(*args):
            @cloudwatched("lambda")
            def _run(func_arn=None):
                with contextlib.ExitStack() as stack:
                    if lock_discriminator:
                        stack.enter_context(LAMBDA_ASYNC_LOCKS.locks[lock_discriminator])
                    # set the invocation time in milliseconds
                    invocation_time = int(time.time() * 1000)
                    # start the execution
                    raised_error = None
                    result = None
                    dlq_sent = None
                    invocation_type = "Event" if asynchronous else "RequestResponse"
                    inv_context = InvocationContext(
                        lambda_function,
                        event=event,
                        function_version=version,
                        context=context,
                        invocation_type=invocation_type,
                    )
                    try:
                        result = self._execute(lambda_function, inv_context)
                    except Exception as e:
                        raised_error = e
                        dlq_sent = handle_error(lambda_function, event, e, asynchronous)
                        raise e
                    finally:
                        self.function_invoke_times[func_arn] = invocation_time
                        callback and callback(
                            result, func_arn, event, error=raised_error, dlq_sent=dlq_sent
                        )
                        lambda_result_to_destination(
                            lambda_function, event, result, asynchronous, raised_error
                        )

                    # return final result
                    return result

            return _run(func_arn=func_arn)

        # Inform users about asynchronous mode of the lambda execution.
        if asynchronous:
            LOG.debug(
                "Lambda executed in Event (asynchronous) mode, no response will be returned to caller"
            )
            FuncThread(do_execute).start()
            return InvocationResult(None, log_output="Lambda executed asynchronously.")

        return do_execute()

    def _execute(self, lambda_function: LambdaFunction, inv_context: InvocationContext):
        """This method must be overwritten by subclasses."""
        raise NotImplementedError

    def startup(self):
        """Called once during startup - can be used, e.g., to prepare Lambda Docker environment"""
        pass

    def cleanup(self, arn=None):
        """Called once during startup - can be used, e.g., to clean up left-over Docker containers"""
        pass

    def provide_file_to_lambda(self, local_file: str, inv_context: InvocationContext) -> str:
        """Make the given file available to the Lambda process (e.g., by copying into the container) for the
        given invocation context; Returns the path to the file that will be available to the Lambda handler."""
        raise NotImplementedError

    def apply_plugin_patches(self, inv_context: InvocationContext) -> Optional[InvocationResult]:
        """Loop through the list of plugins, and apply their patches to the invocation context (if applicable)"""
        invocation_results = []

        for plugin in LambdaExecutorPlugin.get_plugins():
            if not plugin.should_apply(inv_context):
                continue

            # initialize, if not done yet
            if not hasattr(plugin, "_initialized"):
                LOG.debug("Initializing Lambda executor plugin %s", plugin.__class__)
                plugin.initialize()
                plugin._initialized = True

            # invoke plugin to prepare invocation
            inv_options = plugin.prepare_invocation(inv_context)
            if not inv_options:
                continue
            if isinstance(inv_options, InvocationResult):
                invocation_results.append(inv_options)
                continue

            # copy files
            file_keys_map = {}
            for key, file_path in inv_options.files_to_add.items():
                file_in_container = self.provide_file_to_lambda(file_path, inv_context)
                file_keys_map[key] = file_in_container

            # replace placeholders like "{<fileKey>}" with corresponding file path
            for key, file_path in file_keys_map.items():
                for env_key, env_value in inv_options.env_updates.items():
                    inv_options.env_updates[env_key] = str(env_value).replace(
                        "{%s}" % key, file_path
                    )
                if inv_options.updated_command:
                    inv_options.updated_command = inv_options.updated_command.replace(
                        "{%s}" % key, file_path
                    )
                    inv_context.lambda_command = inv_options.updated_command

            # update environment
            inv_context.environment.update(inv_options.env_updates)

            # update handler
            if inv_options.updated_handler:
                inv_context.handler = inv_options.updated_handler

        if invocation_results:
            # TODO: This is currently indeterministic! If multiple execution plugins attempt to return
            #  an invocation result right away, only the first one is returned. We need a more solid
            #  mechanism for conflict resolution if multiple plugins interfere!
            if len(invocation_results) > 1:
                LOG.warning(
                    "Multiple invocation results returned from "
                    "LambdaExecutorPlugin.prepare_invocation calls - choosing the first one: %s",
                    invocation_results,
                )
            return invocation_results[0]

    def process_result_via_plugins(
        self, inv_context: InvocationContext, invocation_result: InvocationResult
    ) -> InvocationResult:
        """Loop through the list of plugins, and apply their post-processing logic to the Lambda invocation result."""
        for plugin in LambdaExecutorPlugin.get_plugins():
            if not plugin.should_apply(inv_context):
                continue
            invocation_result = plugin.process_result(inv_context, invocation_result)
        return invocation_result


class ContainerInfo:
    """Contains basic information about a docker container."""

    def __init__(self, name, entry_point):
        self.name = name
        self.entry_point = entry_point


@dataclasses.dataclass
class LambdaContainerConfiguration(ContainerConfiguration):
    # Files required present in the container for lambda execution
    required_files: List[Tuple[str, str]] = dataclasses.field(default_factory=list)


class LambdaExecutorContainers(LambdaExecutor):
    """Abstract executor class for executing Lambda functions in Docker containers"""

    def execute_in_container(
        self,
        lambda_function: LambdaFunction,
        inv_context: InvocationContext,
        stdin=None,
        background=False,
    ) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def run_lambda_executor(self, lambda_function: LambdaFunction, inv_context: InvocationContext):
        env_vars = inv_context.environment
        runtime = lambda_function.runtime or ""
        event = inv_context.event

        stdin_str = None
        event_body = event if event is not None else env_vars.get("AWS_LAMBDA_EVENT_BODY")
        event_body = json.dumps(event_body) if isinstance(event_body, dict) else event_body
        event_body = event_body or ""
        is_large_event = len(event_body) > MAX_ENV_ARGS_LENGTH

        is_provided = runtime.startswith(LAMBDA_RUNTIME_PROVIDED)
        if (
            not is_large_event
            and lambda_function
            and is_provided
            and env_vars.get("DOCKER_LAMBDA_USE_STDIN") == "1"
        ):
            # Note: certain "provided" runtimes (e.g., Rust programs) can block if we pass in
            # the event payload via stdin, hence we rewrite the command to "echo ... | ..." below
            env_updates = {
                "AWS_LAMBDA_EVENT_BODY": to_str(
                    event_body
                ),  # Note: seems to be needed for provided runtimes!
                "DOCKER_LAMBDA_USE_STDIN": "1",
            }
            env_vars.update(env_updates)
            # Note: $AWS_LAMBDA_COGNITO_IDENTITY='{}' causes Rust Lambdas to hang
            env_vars.pop("AWS_LAMBDA_COGNITO_IDENTITY", None)

        if is_large_event:
            # in case of very large event payloads, we need to pass them via stdin
            LOG.debug(
                "Received large Lambda event payload (length %s) - passing via stdin",
                len(event_body),
            )
            env_vars["DOCKER_LAMBDA_USE_STDIN"] = "1"

        if env_vars.get("DOCKER_LAMBDA_USE_STDIN") == "1":
            stdin_str = event_body
            if not is_provided:
                env_vars.pop("AWS_LAMBDA_EVENT_BODY", None)
        elif "AWS_LAMBDA_EVENT_BODY" not in env_vars:
            env_vars["AWS_LAMBDA_EVENT_BODY"] = to_str(event_body)

        # apply plugin patches
        result = self.apply_plugin_patches(inv_context)
        if isinstance(result, InvocationResult):
            return result

        if config.LAMBDA_DOCKER_FLAGS:
            inv_context.docker_flags = (
                f"{config.LAMBDA_DOCKER_FLAGS} {inv_context.docker_flags or ''}".strip()
            )

        event_stdin_bytes = stdin_str and to_bytes(stdin_str)
        error = None
        try:
            result, log_output = self.execute_in_container(
                lambda_function,
                inv_context,
                stdin=event_stdin_bytes,
            )
        except ContainerException as e:
            result = e.stdout or ""
            log_output = e.stderr or ""
            error = e
        except InvocationException as e:
            result = e.result or ""
            log_output = e.log_output or ""
            error = e
        try:
            result = to_str(result).strip()
        except Exception:
            pass

        # Note: The user's code may have been logging to stderr, in which case the logs
        # will be part of the "result" variable here. Hence, make sure that we extract
        # only the *last* line of "result" and consider anything above that as log output.
        if isinstance(result, str) and "\n" in result:
            lines = result.split("\n")
            idx = last_index_of(
                lines, lambda line: line and not line.startswith(INTERNAL_LOG_PREFIX)
            )
            if idx >= 0:
                result = lines[idx]
                additional_logs = "\n".join(lines[:idx] + lines[idx + 1 :])
                log_output += "\n%s" % additional_logs

        func_arn = lambda_function and lambda_function.arn()

        output = OutputLog(result, log_output)
        LOG.debug(
            f"Lambda {func_arn} result / log output:"
            f"\n{output.stdout_formatted()}"
            f"\n>{output.stderr_formatted()}"
        )

        # store log output - TODO get live logs from `process` above?
        store_lambda_logs(lambda_function, log_output)

        if error:
            output.output_file()
            raise InvocationException(
                "Lambda process returned with error. Result: %s. Output:\n%s"
                % (result, log_output),
                log_output,
                result,
            ) from error

        # create result
        invocation_result = InvocationResult(result, log_output=log_output)
        # run plugins post-processing logic
        invocation_result = self.process_result_via_plugins(inv_context, invocation_result)

        return invocation_result

    def prepare_event(self, environment: Dict, event_body: str) -> bytes:
        """Return the event as a stdin string."""
        # amend the environment variables for execution
        environment["AWS_LAMBDA_EVENT_BODY"] = event_body
        return event_body.encode()

    def _execute(self, lambda_function: LambdaFunction, inv_context: InvocationContext):
        runtime = lambda_function.runtime
        handler = lambda_function.handler
        environment = inv_context.environment = self._prepare_environment(lambda_function)
        event = inv_context.event
        context = inv_context.context

        # configure USE_SSL in environment
        if config.USE_SSL:
            environment["USE_SSL"] = "1"

        # prepare event body
        if not event:
            LOG.info(
                'Empty event body specified for invocation of Lambda "%s"', lambda_function.arn()
            )
            event = {}
        event_body = json.dumps(json_safe(event))
        event_bytes_for_stdin = self.prepare_event(environment, event_body)
        inv_context.event = event_bytes_for_stdin

        Util.inject_endpoints_into_env(environment)
        environment["EDGE_PORT"] = str(config.EDGE_PORT)
        environment[LAMBDA_HANDLER_ENV_VAR_NAME] = handler
        if os.environ.get("HTTP_PROXY"):
            environment["HTTP_PROXY"] = os.environ["HTTP_PROXY"]
        if lambda_function.timeout:
            environment["AWS_LAMBDA_FUNCTION_TIMEOUT"] = str(lambda_function.timeout)
        if context:
            environment["AWS_LAMBDA_FUNCTION_NAME"] = context.function_name
            environment["AWS_LAMBDA_FUNCTION_VERSION"] = context.function_version
            environment["AWS_LAMBDA_FUNCTION_INVOKED_ARN"] = context.invoked_function_arn
            if context.cognito_identity:
                environment["AWS_LAMBDA_COGNITO_IDENTITY"] = json.dumps(context.cognito_identity)
            if context.client_context is not None:
                environment["AWS_LAMBDA_CLIENT_CONTEXT"] = json.dumps(
                    to_str(base64.b64decode(to_bytes(context.client_context)))
                )

        # pass JVM options to the Lambda environment, if configured
        if config.LAMBDA_JAVA_OPTS and is_java_lambda(runtime):
            if environment.get("JAVA_TOOL_OPTIONS"):
                LOG.info(
                    "Skip setting LAMBDA_JAVA_OPTS as JAVA_TOOL_OPTIONS already defined in Lambda env vars"
                )
            else:
                LOG.debug(
                    "Passing JVM options to container environment: JAVA_TOOL_OPTIONS=%s",
                    config.LAMBDA_JAVA_OPTS,
                )
                environment["JAVA_TOOL_OPTIONS"] = config.LAMBDA_JAVA_OPTS

        # accept any self-signed certificates for outgoing calls from the Lambda
        if is_nodejs_runtime(runtime):
            environment["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

        # run Lambda executor and fetch invocation result
        LOG.info("Running lambda: %s", lambda_function.arn())
        result = self.run_lambda_executor(lambda_function=lambda_function, inv_context=inv_context)

        return result

    def provide_file_to_lambda(self, local_file: str, inv_context: InvocationContext) -> str:
        if config.LAMBDA_REMOTE_DOCKER:
            LOG.info("TODO: copy file into container for LAMBDA_REMOTE_DOCKER=1 - %s", local_file)
            return local_file

        mountable_file = Util.get_host_path_for_path_in_docker(local_file)
        _, extension = os.path.splitext(local_file)
        target_file_name = f"{md5(local_file)}{extension}"
        target_path = f"/tmp/{target_file_name}"
        inv_context.docker_flags = inv_context.docker_flags or ""
        inv_context.docker_flags += f"-v {mountable_file}:{target_path}"
        return target_path


class LambdaExecutorReuseContainers(LambdaExecutorContainers):
    """Executor class for executing Lambda functions in re-usable Docker containers"""

    def __init__(self):
        super(LambdaExecutorReuseContainers, self).__init__()
        # locking thread for creation/destruction of docker containers.
        self.docker_container_lock = threading.RLock()

        # On each invocation we try to construct a port unlikely to conflict
        # with a previously invoked lambda function. This is a problem with at
        # least the lambci/lambda:go1.x container, which execs a go program that
        # attempts to bind to the same default port.
        self.next_port = 0
        self.max_port = LAMBDA_SERVER_UNIQUE_PORTS
        self.port_offset = LAMBDA_SERVER_PORT_OFFSET

    def execute_in_container(
        self,
        lambda_function: LambdaFunction,
        inv_context: InvocationContext,
        stdin=None,
        background=False,
    ) -> Tuple[bytes, bytes]:
        func_arn = lambda_function.arn()
        lambda_cwd = lambda_function.cwd
        runtime = lambda_function.runtime
        env_vars = inv_context.environment

        # Choose a port for this invocation
        with self.docker_container_lock:
            env_vars["_LAMBDA_SERVER_PORT"] = str(self.next_port + self.port_offset)
            self.next_port = (self.next_port + 1) % self.max_port

        # create/verify the docker container is running.
        LOG.debug(
            'Priming docker container with runtime "%s" and arn "%s".',
            runtime,
            func_arn,
        )
        container_info = self.prime_docker_container(
            lambda_function, dict(env_vars), lambda_cwd, inv_context.docker_flags
        )

        if not inv_context.lambda_command and inv_context.handler:
            command = shlex.split(container_info.entry_point)
            command.append(inv_context.handler)
            inv_context.lambda_command = command

        lambda_docker_ip = DOCKER_CLIENT.get_container_ip(container_info.name)

        if not self._should_use_stay_open_mode(lambda_function, lambda_docker_ip, check_port=True):
            LOG.debug("Using 'docker exec' to run invocation in docker-reuse Lambda container")
            # disable stay open mode for this one, to prevent starting runtime API server
            env_vars["DOCKER_LAMBDA_STAY_OPEN"] = None
            return DOCKER_CLIENT.exec_in_container(
                container_name_or_id=container_info.name,
                command=inv_context.lambda_command,
                interactive=True,
                env_vars=env_vars,
                stdin=stdin,
            )

        inv_result = self.invoke_lambda(lambda_function, inv_context, lambda_docker_ip)
        return (inv_result.result, inv_result.log_output)

    def invoke_lambda(
        self,
        lambda_function: LambdaFunction,
        inv_context: InvocationContext,
        lambda_docker_ip=None,
    ) -> InvocationResult:
        full_url = self._get_lambda_stay_open_url(lambda_docker_ip)

        client = aws_stack.connect_to_service("lambda", endpoint_url=full_url)
        event = inv_context.event or "{}"

        LOG.debug(f"Calling {full_url} to run invocation in docker-reuse Lambda container")
        response = client.invoke(
            FunctionName=lambda_function.name(),
            InvocationType=inv_context.invocation_type,
            Payload=to_bytes(event),
            LogType="Tail",
        )

        log_output = base64.b64decode(response.get("LogResult") or b"").decode("utf-8")
        result = response["Payload"].read().decode("utf-8")

        if "FunctionError" in response:
            raise InvocationException(
                "Lambda process returned with error. Result: %s. Output:\n%s"
                % (result, log_output),
                log_output,
                result,
            )

        return InvocationResult(result, log_output)

    def _should_use_stay_open_mode(
        self,
        lambda_function: LambdaFunction,
        lambda_docker_ip: Optional[str] = None,
        check_port: bool = False,
    ) -> bool:
        """Return whether to use stay-open execution mode - if we're running in Docker, the given IP
        is defined, and if the target API endpoint is available (optionally, if check_port is True)."""
        if not lambda_docker_ip:
            func_arn = lambda_function.arn()
            container_name = self.get_container_name(func_arn)
            lambda_docker_ip = DOCKER_CLIENT.get_container_ip(container_name_or_id=container_name)
        should_use = lambda_docker_ip and config.LAMBDA_STAY_OPEN_MODE
        if not should_use or not check_port:
            return should_use
        full_url = self._get_lambda_stay_open_url(lambda_docker_ip)
        return is_port_open(full_url)

    def _get_lambda_stay_open_url(self, lambda_docker_ip: str) -> str:
        return f"http://{lambda_docker_ip}:{STAY_OPEN_API_PORT}"

    def _execute(self, func_arn: str, *args, **kwargs) -> InvocationResult:
        if not LAMBDA_CONCURRENCY_LOCK.get(func_arn):
            concurrency_lock = threading.RLock()
            LAMBDA_CONCURRENCY_LOCK[func_arn] = concurrency_lock
        with LAMBDA_CONCURRENCY_LOCK[func_arn]:
            return super(LambdaExecutorReuseContainers, self)._execute(func_arn, *args, **kwargs)

    def startup(self):
        self.cleanup()
        # start a process to remove idle containers
        if config.LAMBDA_REMOVE_CONTAINERS:
            self.start_idle_container_destroyer_interval()

    def cleanup(self, arn: str = None):
        if arn:
            self.function_invoke_times.pop(arn, None)
            return self.destroy_docker_container(arn)
        self.function_invoke_times = {}
        return self.destroy_existing_docker_containers()

    def prime_docker_container(
        self,
        lambda_function: LambdaFunction,
        env_vars: Dict,
        lambda_cwd: str,
        docker_flags: str = None,
    ):
        """
        Prepares a persistent docker container for a specific function.
        :param lambda_function: The Details of the lambda function.
        :param env_vars: The environment variables for the lambda.
        :param lambda_cwd: The local directory containing the code for the lambda function.
        :return: ContainerInfo class containing the container name and default entry point.
        """
        with self.docker_container_lock:
            # Get the container name and id.
            func_arn = lambda_function.arn()
            container_name = self.get_container_name(func_arn)

            status = self.get_docker_container_status(func_arn)
            LOG.debug('Priming Docker container (status "%s"): %s', status, container_name)

            docker_image = Util.docker_image_for_lambda(lambda_function)

            # Container is not running or doesn't exist.
            if status < 1:
                # Make sure the container does not exist in any form/state.
                self.destroy_docker_container(func_arn)

                # get container startup command and run it
                LOG.debug("Creating container: %s", container_name)
                self.create_container(lambda_function, env_vars, lambda_cwd, docker_flags)

                LOG.debug("Starting docker-reuse Lambda container: %s", container_name)
                DOCKER_CLIENT.start_container(container_name)

                def wait_up():
                    cont_status = DOCKER_CLIENT.get_container_status(container_name)
                    assert cont_status == DockerContainerStatus.UP
                    if not in_docker():
                        return
                    # if we're executing in Docker using stay-open mode, additionally check if the target is available
                    lambda_docker_ip = DOCKER_CLIENT.get_container_ip(container_name)
                    if self._should_use_stay_open_mode(lambda_function, lambda_docker_ip):
                        full_url = self._get_lambda_stay_open_url(lambda_docker_ip)
                        wait_for_port_open(full_url, sleep_time=0.5, retries=8)

                # give the container some time to start up
                retry(wait_up, retries=15, sleep=0.8)

            container_network = self.get_docker_container_network(func_arn)
            entry_point = DOCKER_CLIENT.get_image_entrypoint(docker_image)

            LOG.debug(
                'Using entrypoint "%s" for container "%s" on network "%s".',
                entry_point,
                container_name,
                container_network,
            )

            return ContainerInfo(container_name, entry_point)

    def create_container(
        self,
        lambda_function: LambdaFunction,
        env_vars: Dict,
        lambda_cwd: str,
        docker_flags: str = None,
    ):
        docker_image = Util.docker_image_for_lambda(lambda_function)
        container_config = LambdaContainerConfiguration(image_name=docker_image)
        container_config.name = self.get_container_name(lambda_function.arn())

        # make sure AWS_LAMBDA_EVENT_BODY is not set (otherwise causes issues with "docker exec ..." above)
        env_vars.pop("AWS_LAMBDA_EVENT_BODY", None)
        container_config.env_vars = env_vars

        container_config.network = get_container_network_for_lambda()
        container_config.additional_flags = docker_flags

        container_config.dns = config.LAMBDA_DOCKER_DNS

        if lambda_cwd:
            if config.LAMBDA_REMOTE_DOCKER:
                container_config.required_files.append((f"{lambda_cwd}/.", DOCKER_TASK_FOLDER))
            else:
                lambda_cwd_on_host = Util.get_host_path_for_path_in_docker(lambda_cwd)
                # TODO not necessary after Windows 10. Should be deprecated and removed in the future
                if ":" in lambda_cwd and "\\" in lambda_cwd:
                    lambda_cwd_on_host = Util.format_windows_path(lambda_cwd_on_host)
                container_config.required_files.append((lambda_cwd_on_host, DOCKER_TASK_FOLDER))

        container_config.entrypoint = "/bin/bash"
        container_config.interactive = True

        if config.LAMBDA_STAY_OPEN_MODE:
            container_config.env_vars["DOCKER_LAMBDA_STAY_OPEN"] = "1"
            # clear docker lambda use stdin since not relevant with stay open
            container_config.env_vars.pop("DOCKER_LAMBDA_USE_STDIN", None)
            container_config.entrypoint = None
            container_config.command = [lambda_function.handler]
            container_config.interactive = False

        # default settings
        container_config.remove = True
        container_config.detach = True

        on_docker_reuse_container_creation.run(lambda_function, container_config)

        if not config.LAMBDA_REMOTE_DOCKER and container_config.required_files:
            container_config.volumes = container_config.required_files

        LOG.debug(
            "Creating docker-reuse Lambda container %s from image %s",
            container_config.name,
            container_config.image_name,
        )
        container_id = DOCKER_CLIENT.create_container(
            image_name=container_config.image_name,
            remove=container_config.remove,
            interactive=container_config.interactive,
            detach=container_config.detach,
            name=container_config.name,
            entrypoint=container_config.entrypoint,
            command=container_config.command,
            network=container_config.network,
            env_vars=container_config.env_vars,
            dns=container_config.dns,
            mount_volumes=container_config.volumes,
            additional_flags=container_config.additional_flags,
            workdir=container_config.workdir,
            user=container_config.user,
            cap_add=container_config.cap_add,
        )
        if config.LAMBDA_REMOTE_DOCKER and container_config.required_files:
            for source, target in container_config.required_files:
                LOG.debug('Copying "%s" to "%s:%s".', source, container_config.name, target)
                DOCKER_CLIENT.copy_into_container(container_config.name, source, target)
        return container_id

    def destroy_docker_container(self, func_arn):
        """
        Stops and/or removes a docker container for a specific lambda function ARN.
        :param func_arn: The ARN of the lambda function.
        :return: None
        """
        with self.docker_container_lock:
            status = self.get_docker_container_status(func_arn)

            # Get the container name and id.
            container_name = self.get_container_name(func_arn)
            if status == 1:
                LOG.debug("Stopping container: %s", container_name)
                DOCKER_CLIENT.stop_container(container_name)
                status = self.get_docker_container_status(func_arn)

            if status == -1:
                LOG.debug("Removing container: %s", container_name)
                rm_docker_container(container_name, safe=True)

            # clean up function invoke times, as some init logic depends on this
            self.function_invoke_times.pop(func_arn, None)

    def get_all_container_names(self):
        """
        Returns a list of container names for lambda containers.
        :return: A String[] localstack docker container names for each function.
        """
        with self.docker_container_lock:
            LOG.debug("Getting all lambda containers names.")
            list_result = DOCKER_CLIENT.list_containers(
                filter=f"name={self.get_container_prefix()}*"
            )
            container_names = list(map(lambda container: container["name"], list_result))

            return container_names

    def destroy_existing_docker_containers(self):
        """
        Stops and/or removes all lambda docker containers for localstack.
        :return: None
        """
        with self.docker_container_lock:
            container_names = self.get_all_container_names()

            LOG.debug("Removing %d containers.", len(container_names))
            for container_name in container_names:
                DOCKER_CLIENT.remove_container(container_name)

    def get_docker_container_status(self, func_arn):
        """
        Determine the status of a docker container.
        :param func_arn: The ARN of the lambda function.
        :return: 1 If the container is running,
        -1 if the container exists but is not running
        0 if the container does not exist.
        """
        with self.docker_container_lock:
            # Get the container name and id.
            container_name = self.get_container_name(func_arn)

            container_status = DOCKER_CLIENT.get_container_status(container_name)

            return container_status.value

    def get_docker_container_network(self, func_arn):
        """
        Determine the network of a docker container.
        :param func_arn: The ARN of the lambda function.
        :return: name of the container network
        """
        with self.docker_container_lock:
            status = self.get_docker_container_status(func_arn)
            # container does not exist
            if status == 0:
                return ""

            # Get the container name.
            container_name = self.get_container_name(func_arn)

            container_network = DOCKER_CLIENT.get_networks(container_name)[0]

            return container_network

    def idle_container_destroyer(self):
        """
        Iterates though all the lambda containers and destroys any container that has
        been inactive for longer than MAX_CONTAINER_IDLE_TIME_MS.
        :return: None
        """
        LOG.debug("Checking if there are idle containers ...")
        current_time = int(time.time() * 1000)
        for func_arn, last_run_time in dict(self.function_invoke_times).items():
            duration = current_time - last_run_time

            # not enough idle time has passed
            if duration < MAX_CONTAINER_IDLE_TIME_MS:
                continue

            # container has been idle, destroy it.
            self.destroy_docker_container(func_arn)

    def start_idle_container_destroyer_interval(self):
        """
        Starts a repeating timer that triggers start_idle_container_destroyer_interval every 60 seconds.
        Thus checking for idle containers and destroying them.
        :return: None
        """
        self.idle_container_destroyer()
        threading.Timer(60.0, self.start_idle_container_destroyer_interval).start()

    def get_container_prefix(self) -> str:
        """
        Returns the prefix of all docker-reuse lambda containers for this LocalStack instance
        :return: Lambda container name prefix
        """
        return f"{bootstrap.get_main_container_name()}_lambda_"

    def get_container_name(self, func_arn):
        """
        Given a function ARN, returns a valid docker container name.
        :param func_arn: The ARN of the lambda function.
        :return: A docker compatible name for the arn.
        """
        return self.get_container_prefix() + re.sub(r"[^a-zA-Z0-9_.-]", "_", func_arn)


class LambdaExecutorSeparateContainers(LambdaExecutorContainers):
    def __init__(self):
        super(LambdaExecutorSeparateContainers, self).__init__()
        self.max_port = LAMBDA_API_UNIQUE_PORTS
        self.port_offset = LAMBDA_API_PORT_OFFSET

    def prepare_event(self, environment: Dict, event_body: str) -> bytes:
        # Tell Lambci to use STDIN for the event
        environment["DOCKER_LAMBDA_USE_STDIN"] = "1"
        return event_body.encode()

    def execute_in_container(
        self,
        lambda_function: LambdaFunction,
        inv_context: InvocationContext,
        stdin=None,
        background=False,
    ) -> Tuple[bytes, bytes]:
        docker_image = Util.docker_image_for_lambda(lambda_function)
        container_config = LambdaContainerConfiguration(image_name=docker_image)

        container_config.env_vars = inv_context.environment
        if inv_context.lambda_command:
            container_config.entrypoint = ""
        elif inv_context.handler:
            inv_context.lambda_command = inv_context.handler

        # add Docker Lambda env vars
        container_config.network = get_container_network_for_lambda()
        if container_config.network == "host":
            port = get_free_tcp_port()
            container_config.env_vars["DOCKER_LAMBDA_API_PORT"] = port
            container_config.env_vars["DOCKER_LAMBDA_RUNTIME_PORT"] = port

        container_config.additional_flags = inv_context.docker_flags or ""
        container_config.dns = config.LAMBDA_DOCKER_DNS
        container_config.ports = PortMappings()
        if Util.debug_java_port:
            container_config.ports.add(Util.debug_java_port)
        container_config.command = inv_context.lambda_command
        container_config.remove = True
        container_config.interactive = True
        container_config.detach = background

        lambda_cwd = lambda_function.cwd
        if lambda_cwd:
            if config.LAMBDA_REMOTE_DOCKER:
                container_config.required_files.append((f"{lambda_cwd}/.", DOCKER_TASK_FOLDER))
            else:
                container_config.required_files.append(
                    (Util.get_host_path_for_path_in_docker(lambda_cwd), DOCKER_TASK_FOLDER)
                )

        # running hooks to modify execution parameters
        on_docker_separate_execution.run(lambda_function, container_config)

        # actual execution
        # TODO make container client directly accept ContainerConfiguration (?)
        if not config.LAMBDA_REMOTE_DOCKER and container_config.required_files:
            container_config.volumes = container_config.volumes or []
            container_config.volumes += container_config.required_files

        container_id = DOCKER_CLIENT.create_container(
            image_name=container_config.image_name,
            interactive=container_config.interactive,
            entrypoint=container_config.entrypoint,
            remove=container_config.remove,
            network=container_config.network,
            env_vars=container_config.env_vars,
            dns=container_config.dns,
            additional_flags=container_config.additional_flags,
            ports=container_config.ports,
            command=container_config.command,
            mount_volumes=container_config.volumes,
            workdir=container_config.workdir,
            user=container_config.user,
            cap_add=container_config.cap_add,
        )
        if config.LAMBDA_REMOTE_DOCKER:
            for source, target in container_config.required_files:
                DOCKER_CLIENT.copy_into_container(container_id, source, target)
        return DOCKER_CLIENT.start_container(
            container_id,
            interactive=not container_config.detach,
            attach=not container_config.detach,
            stdin=stdin,
        )


class LambdaExecutorLocal(LambdaExecutor):

    # maps functionARN -> functionVersion -> callable used to invoke a Lambda function locally
    FUNCTION_CALLABLES: Dict[str, Dict[str, Callable]] = {}

    def _execute_in_custom_runtime(
        self, cmd: Union[str, List[str]], lambda_function: LambdaFunction = None
    ) -> InvocationResult:
        """
        Generic run function for executing lambdas in custom runtimes.

        :param cmd: the command to execute
        :param lambda_function: function details
        :return: the InvocationResult
        """

        env_vars = lambda_function and lambda_function.envvars
        kwargs = {"stdin": True, "inherit_env": True, "asynchronous": True, "env_vars": env_vars}

        process = run(cmd, stderr=subprocess.PIPE, outfile=subprocess.PIPE, **kwargs)
        result, log_output = process.communicate()

        try:
            result = to_str(result).strip()
        except Exception:
            pass
        log_output = to_str(log_output).strip()
        return_code = process.returncode

        # Note: The user's code may have been logging to stderr, in which case the logs
        # will be part of the "result" variable here. Hence, make sure that we extract
        # only the *last* line of "result" and consider anything above that as log output.
        # TODO: not sure if this code is needed/used
        if isinstance(result, str) and "\n" in result:
            lines = result.split("\n")
            idx = last_index_of(
                lines, lambda line: line and not line.startswith(INTERNAL_LOG_PREFIX)
            )
            if idx >= 0:
                result = lines[idx]
                additional_logs = "\n".join(lines[:idx] + lines[idx + 1 :])
                log_output += "\n%s" % additional_logs

        func_arn = lambda_function and lambda_function.arn()
        output = OutputLog(result, log_output)
        LOG.debug(
            f"Lambda {func_arn} result / log output:"
            f"\n{output.stdout_formatted()}"
            f"\n>{output.stderr_formatted()}"
        )

        # store log output - TODO get live logs from `process` above?
        # store_lambda_logs(lambda_function, log_output)

        if return_code != 0:
            output.output_file()
            raise InvocationException(
                "Lambda process returned error status code: %s. Result: %s. Output:\n%s"
                % (return_code, result, log_output),
                log_output,
                result,
            )

        invocation_result = InvocationResult(result, log_output=log_output)
        return invocation_result

    def _execute(
        self, lambda_function: LambdaFunction, inv_context: InvocationContext
    ) -> InvocationResult:

        # apply plugin patches to prepare invocation context
        result = self.apply_plugin_patches(inv_context)
        if isinstance(result, InvocationResult):
            return result

        lambda_cwd = lambda_function.cwd
        environment = self._prepare_environment(lambda_function)

        environment["LOCALSTACK_HOSTNAME"] = config.LOCALSTACK_HOSTNAME
        environment["EDGE_PORT"] = str(config.EDGE_PORT)
        if lambda_function.timeout:
            environment["AWS_LAMBDA_FUNCTION_TIMEOUT"] = str(lambda_function.timeout)
        context = inv_context.context
        if context:
            environment["AWS_LAMBDA_FUNCTION_NAME"] = context.function_name
            environment["AWS_LAMBDA_FUNCTION_VERSION"] = context.function_version
            environment["AWS_LAMBDA_FUNCTION_INVOKED_ARN"] = context.invoked_function_arn
            environment["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"] = str(context.memory_limit_in_mb)

        # execute the Lambda function in a forked sub-process, sync result via queue
        queue = Queue()

        lambda_function_callable = self.get_lambda_callable(
            lambda_function, qualifier=inv_context.function_version
        )

        def do_execute():
            # now we're executing in the child process, safe to change CWD and ENV
            result = None
            try:
                if lambda_cwd:
                    os.chdir(lambda_cwd)
                    sys.path.insert(0, "")
                if environment:
                    os.environ.update(environment)
                # set default env variables required for most Lambda handlers
                self.set_default_env_variables()
                # run the actual handler function
                result = lambda_function_callable(inv_context.event, context)
            except Exception as e:
                result = str(e)
                sys.stderr.write("%s %s" % (e, traceback.format_exc()))
                raise
            finally:
                queue.put(result)

        process = Process(target=do_execute)
        start_time = now(millis=True)
        error = None
        with CaptureOutput() as c:
            try:
                process.run()
            except Exception as e:
                error = e
        result = queue.get()
        end_time = now(millis=True)

        # Make sure to keep the log line below, to ensure the log stream gets created
        request_id = long_uid()
        log_output = 'START %s: Lambda %s started via "local" executor ...' % (
            request_id,
            lambda_function.arn(),
        )
        # TODO: Interweaving stdout/stderr currently not supported
        for stream in (c.stdout(), c.stderr()):
            if stream:
                log_output += ("\n" if log_output else "") + stream
        if isinstance(result, InvocationResult) and result.log_output:
            log_output += "\n" + result.log_output
        log_output += "\nEND RequestId: %s" % request_id
        log_output += "\nREPORT RequestId: %s Duration: %s ms" % (
            request_id,
            int((end_time - start_time) * 1000),
        )

        # store logs to CloudWatch
        store_lambda_logs(lambda_function, log_output)

        result = result.result if isinstance(result, InvocationResult) else result

        if error:
            LOG.info(
                'Error executing Lambda "%s": %s %s',
                lambda_function.arn(),
                error,
                "".join(traceback.format_tb(error.__traceback__)),
            )
            raise InvocationException(result, log_output)

        # construct final invocation result
        invocation_result = InvocationResult(result, log_output=log_output)
        # run plugins post-processing logic
        invocation_result = self.process_result_via_plugins(inv_context, invocation_result)
        return invocation_result

    def provide_file_to_lambda(self, local_file: str, inv_context: InvocationContext) -> str:
        # This is a no-op for local executors - simply return the given local file path
        return local_file

    def execute_java_lambda(
        self, event, context, main_file, lambda_function: LambdaFunction = None
    ) -> InvocationResult:
        lambda_function.envvars = lambda_function.envvars or {}
        java_opts = config.LAMBDA_JAVA_OPTS or ""

        handler = lambda_function.handler
        lambda_function.envvars[LAMBDA_HANDLER_ENV_VAR_NAME] = handler

        event_file = EVENT_FILE_PATTERN.replace("*", short_uid())
        save_file(event_file, json.dumps(json_safe(event)))
        TMP_FILES.append(event_file)

        classpath = "%s:%s:%s" % (
            main_file,
            Util.get_java_classpath(main_file),
            LAMBDA_EXECUTOR_JAR,
        )
        cmd = "java %s -cp %s %s %s" % (
            java_opts,
            classpath,
            LAMBDA_EXECUTOR_CLASS,
            event_file,
        )

        # apply plugin patches
        inv_context = InvocationContext(
            lambda_function, event, environment=lambda_function.envvars, lambda_command=cmd
        )
        result = self.apply_plugin_patches(inv_context)
        if isinstance(result, InvocationResult):
            return result

        cmd = inv_context.lambda_command
        LOG.info(cmd)

        # execute Lambda and get invocation result
        invocation_result = self._execute_in_custom_runtime(cmd, lambda_function=lambda_function)

        return invocation_result

    def execute_javascript_lambda(
        self, event, context, main_file, lambda_function: LambdaFunction = None
    ):
        handler = lambda_function.handler
        function = handler.split(".")[-1]
        event_json_string = "%s" % (json.dumps(json_safe(event)) if event else "{}")
        context_json_string = "%s" % (json.dumps(context.__dict__) if context else "{}")
        cmd = [
            "node",
            "-e",
            f'const res = require("{main_file}").{function}({event_json_string},{context_json_string}); '
            f"const log = (rs) => console.log(JSON.stringify(rs)); "
            "res && res.then ? res.then(r => log(r)) : log(res)",
        ]
        LOG.info(cmd)
        result = self._execute_in_custom_runtime(cmd, lambda_function=lambda_function)
        return result

    def execute_go_lambda(self, event, context, main_file, lambda_function: LambdaFunction = None):

        if lambda_function:
            lambda_function.envvars["AWS_LAMBDA_FUNCTION_HANDLER"] = main_file
            lambda_function.envvars["AWS_LAMBDA_EVENT_BODY"] = json.dumps(json_safe(event))
        else:
            LOG.warning("Unable to get function details for local execution of Golang Lambda")

        cmd = GO_LAMBDA_RUNTIME
        LOG.debug("Running Golang Lambda with runtime: %s", cmd)
        result = self._execute_in_custom_runtime(cmd, lambda_function=lambda_function)
        return result

    @staticmethod
    def set_default_env_variables():
        # set default env variables required for most Lambda handlers
        default_env_vars = {"AWS_DEFAULT_REGION": aws_stack.get_region()}
        env_vars_before = {var: os.environ.get(var) for var in default_env_vars}
        os.environ.update({k: v for k, v in default_env_vars.items() if not env_vars_before.get(k)})
        return env_vars_before

    @staticmethod
    def reset_default_env_variables(env_vars_before):
        for env_name, env_value in env_vars_before.items():
            env_value_before = env_vars_before.get(env_name)
            os.environ[env_name] = env_value_before or ""
            if env_value_before is None:
                os.environ.pop(env_name, None)

    @classmethod
    def get_lambda_callable(cls, function: LambdaFunction, qualifier: str = None) -> Callable:
        """Returns the function Callable for invoking the given function locally"""
        qualifier = function.get_qualifier_version(qualifier)
        func_dict = cls.FUNCTION_CALLABLES.get(function.arn()) or {}
        # TODO: function versioning and qualifiers should be refactored and designed properly!
        callable = func_dict.get(qualifier) or func_dict.get(LambdaFunction.QUALIFIER_LATEST)
        if not callable:
            raise Exception(
                f"Unable to find callable for Lambda function {function.arn()} - {qualifier}"
            )
        return callable

    @classmethod
    def add_function_callable(cls, function: LambdaFunction, lambda_handler: Callable):
        """Sets the function Callable for invoking the $LATEST version of the Lambda function."""
        func_dict = cls.FUNCTION_CALLABLES.setdefault(function.arn(), {})
        qualifier = function.get_qualifier_version(LambdaFunction.QUALIFIER_LATEST)
        func_dict[qualifier] = lambda_handler


class Util:
    debug_java_port = False

    @classmethod
    def get_java_opts(cls):
        opts = config.LAMBDA_JAVA_OPTS or ""
        # Replace _debug_port_ with a random free port
        if "_debug_port_" in opts:
            if not cls.debug_java_port:
                cls.debug_java_port = get_free_tcp_port()
            opts = opts.replace("_debug_port_", ("%s" % cls.debug_java_port))
        else:
            # Parse the debug port from opts
            m = re.match(".*address=(.+:)?(\\d+).*", opts)
            if m is not None:
                cls.debug_java_port = m.groups()[1]

        return opts

    @classmethod
    def get_host_path_for_path_in_docker(cls, path):
        return re.sub(r"^%s/(.*)$" % config.dirs.tmp, r"%s/\1" % config.dirs.functions, path)

    @classmethod
    def format_windows_path(cls, path):
        temp = path.replace(":", "").replace("\\", "/")
        if len(temp) >= 1 and temp[:1] != "/":
            temp = "/" + temp
        temp = "%s%s" % (config.WINDOWS_DOCKER_MOUNT_PREFIX, temp)
        return temp

    @classmethod
    def docker_image_for_lambda(cls, lambda_function: LambdaFunction):
        runtime = lambda_function.runtime or ""
        if lambda_function.code.get("ImageUri"):
            LOG.warning(
                "ImageUri is set: Using Lambda container images is only supported in LocalStack Pro"
            )
        docker_tag = runtime
        docker_image = config.LAMBDA_CONTAINER_REGISTRY
        if runtime == "nodejs14.x" and docker_image == DEFAULT_LAMBDA_CONTAINER_REGISTRY:
            # TODO temporary fix until lambci image for nodejs14.x becomes available
            docker_image = "localstack/lambda-js"
        if runtime == "python3.9" and docker_image == DEFAULT_LAMBDA_CONTAINER_REGISTRY:
            # TODO temporary fix until we support AWS images via https://github.com/localstack/localstack/pull/4734
            docker_image = "mlupin/docker-lambda"
        return "%s:%s" % (docker_image, docker_tag)

    @classmethod
    def get_java_classpath(cls, archive):
        """
        Return the Java classpath, using the parent folder of the
        given archive as the base folder.

        The result contains any *.jar files in the base folder, as
        well as any JAR files in the "lib/*" subfolder living
        alongside the supplied java archive (.jar or .zip).

        :param archive: an absolute path to a .jar or .zip Java archive
        :return: the Java classpath, relative to the base dir of "archive"
        """
        entries = ["."]
        base_dir = os.path.dirname(archive)
        for pattern in ["%s/*.jar", "%s/lib/*.jar", "%s/java/lib/*.jar", "%s/*.zip"]:
            for entry in glob.glob(pattern % base_dir):
                if os.path.realpath(archive) != os.path.realpath(entry):
                    entries.append(os.path.relpath(entry, base_dir))
        # make sure to append the localstack-utils.jar at the end of the classpath
        # https://github.com/localstack/localstack/issues/1160
        entries.append(os.path.relpath(archive, base_dir))
        entries.append("*.jar")
        entries.append("java/lib/*.jar")
        result = ":".join(entries)
        return result

    @staticmethod
    def mountable_tmp_file():
        f = os.path.join(config.dirs.tmp, short_uid())
        TMP_FILES.append(f)
        return f

    @staticmethod
    def inject_endpoints_into_env(env_vars: Dict[str, str]):
        env_vars = env_vars or {}
        main_endpoint = get_main_endpoint_from_container()
        if not env_vars.get("LOCALSTACK_HOSTNAME"):
            env_vars["LOCALSTACK_HOSTNAME"] = main_endpoint
        return env_vars


class OutputLog:

    __slots__ = ["_stdout", "_stderr"]

    def __init__(self, stdout, stderr):
        self._stdout = stdout
        self._stderr = stderr

    def stderr_formatted(self, truncated_to: int = LAMBDA_TRUNCATE_STDOUT):
        return truncate(to_str(self._stderr).strip().replace("\n", "\n> "), truncated_to)

    def stdout_formatted(self, truncated_to: int = LAMBDA_TRUNCATE_STDOUT):
        return truncate(to_str(self._stdout).strip(), truncated_to)

    def output_file(self):
        with tempfile.NamedTemporaryFile(
            dir=TMP_FOLDER, delete=False, suffix=".log", prefix="lambda_"
        ) as f:
            LOG.info(f"writing log to file '{f.name}'")
            f.write(self._stderr)


# --------------
# GLOBAL STATE
# --------------

EXECUTOR_LOCAL = LambdaExecutorLocal()
EXECUTOR_CONTAINERS_SEPARATE = LambdaExecutorSeparateContainers()
EXECUTOR_CONTAINERS_REUSE = LambdaExecutorReuseContainers()
DEFAULT_EXECUTOR = EXECUTOR_CONTAINERS_SEPARATE
# the keys of AVAILABLE_EXECUTORS map to the LAMBDA_EXECUTOR config variable
AVAILABLE_EXECUTORS = {
    "local": EXECUTOR_LOCAL,
    "docker": EXECUTOR_CONTAINERS_SEPARATE,
    "docker-reuse": EXECUTOR_CONTAINERS_REUSE,
}
