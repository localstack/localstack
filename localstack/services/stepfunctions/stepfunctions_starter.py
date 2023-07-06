import logging
import subprocess

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.connect import connect_to
from localstack.services.infra import do_run, log_startup_message
from localstack.services.stepfunctions.packages import stepfunctions_local_package
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open
from localstack.utils.net import wait_for_port_closed
from localstack.utils.run import ShellCommandThread, wait_for_process_to_be_killed
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"

# todo: will be replaced with plugin mechanism
PROCESS_THREAD: ShellCommandThread | subprocess.Popen | None = None


# TODO: pass env more explicitly
def get_command(backend_port):
    install_dir_stepfunctions = stepfunctions_local_package.get_installed_dir()
    cmd = (
        "cd %s; PORT=%s java "
        "-javaagent:aspectjweaver-1.9.7.jar "
        "-Dorg.aspectj.weaver.loadtime.configuration=META-INF/aop.xml "
        "-Dcom.amazonaws.sdk.disableCertChecking -Xmx%s "
        "-jar StepFunctionsLocal.jar --aws-account %s"
    ) % (
        install_dir_stepfunctions,
        backend_port,
        MAX_HEAP_SIZE,
        get_aws_account_id(),
    )
    if config.STEPFUNCTIONS_LAMBDA_ENDPOINT.lower() != "default":
        lambda_endpoint = config.STEPFUNCTIONS_LAMBDA_ENDPOINT or aws_stack.get_local_service_url(
            "lambda"
        )
        cmd += f" --lambda-endpoint {lambda_endpoint}"
    # add service endpoint flags
    services = [
        "athena",
        "batch",
        "dynamodb",
        "ecs",
        "eks",
        "events",
        "glue",
        "sagemaker",
        "sns",
        "sqs",
        "stepfunctions",
    ]
    for service in services:
        flag = f"--{service}-endpoint"
        if service == "stepfunctions":
            flag = "--step-functions-endpoint"
        elif service == "events":
            flag = "--eventbridge-endpoint"
        elif service in ["athena", "eks"]:
            flag = f"--step-functions-{service}"
        endpoint = aws_stack.get_local_service_url(service)
        cmd += f" {flag} {endpoint}"

    return cmd


def start_stepfunctions(asynchronous: bool = True, persistence_path: str | None = None):
    # TODO: introduce Server abstraction for StepFunctions process
    global PROCESS_THREAD
    backend_port = config.LOCAL_PORT_STEPFUNCTIONS
    stepfunctions_local_package.install()
    cmd = get_command(backend_port)
    log_startup_message("StepFunctions")
    # TODO: change ports in stepfunctions.jar, then update here
    PROCESS_THREAD = do_run(
        cmd,
        asynchronous,
        strip_color=True,
        env_vars={
            "EDGE_PORT": config.EDGE_PORT_HTTP or config.EDGE_PORT,
            "EDGE_PORT_HTTP": config.EDGE_PORT_HTTP or config.EDGE_PORT,
            "DATA_DIR": persistence_path or config.dirs.data,
        },
    )
    return PROCESS_THREAD


def wait_for_stepfunctions():
    retry(check_stepfunctions, sleep=0.5, retries=15)


def stop_stepfunctions():
    if not PROCESS_THREAD or not PROCESS_THREAD.process:
        return
    LOG.debug("Restarting StepFunctions process ...")

    pid = PROCESS_THREAD.process.pid
    PROCESS_THREAD.stop()
    wait_for_port_closed(config.LOCAL_PORT_STEPFUNCTIONS, sleep_time=0.5, retries=15)
    try:
        # TODO: currently failing in CI (potentially due to a defunct process) - need to investigate!
        wait_for_process_to_be_killed(pid, sleep=0.3, retries=10)
    except Exception as e:
        LOG.warning("StepFunctions process not properly terminated: %s", e)


def check_stepfunctions(expect_shutdown: bool = False, print_error: bool = False) -> None:
    out = None
    try:
        wait_for_port_open(config.LOCAL_PORT_STEPFUNCTIONS, sleep_time=2)
        endpoint_url = f"http://127.0.0.1:{config.LOCAL_PORT_STEPFUNCTIONS}"
        out = connect_to(endpoint_url=endpoint_url).stepfunctions.list_state_machines()
    except Exception:
        if print_error:
            LOG.exception("StepFunctions health check failed")

    if expect_shutdown:
        assert out is None
    else:
        assert out and isinstance(out.get("stateMachines"), list)
