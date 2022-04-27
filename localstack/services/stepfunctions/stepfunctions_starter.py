import logging

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import install
from localstack.services.infra import do_run, log_startup_message
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"

# todo: will be replaced with plugin mechanism
PROCESS_THREAD = None


# TODO: pass env more explicitly
def get_command(backend_port):
    cmd = (
        "cd %s; PORT=%s java "
        "-javaagent:aspectjweaver-1.9.7.jar "
        "-Dorg.aspectj.weaver.loadtime.configuration=META-INF/aop.xml "
        "-Dcom.amazonaws.sdk.disableCertChecking -Xmx%s "
        "-jar StepFunctionsLocal.jar --aws-account %s"
    ) % (
        install.INSTALL_DIR_STEPFUNCTIONS,
        backend_port,
        MAX_HEAP_SIZE,
        TEST_AWS_ACCOUNT_ID,
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


def start_stepfunctions(asynchronous=True):
    # TODO: introduce Server abstraction for StepFunctions process
    global PROCESS_THREAD
    backend_port = config.LOCAL_PORT_STEPFUNCTIONS
    install.install_stepfunctions_local()
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
            "DATA_DIR": config.DATA_DIR,
        },
    )
    return PROCESS_THREAD


def wait_for_stepfunctions():
    retry(check_stepfunctions, sleep=0.5, retries=15)


def check_stepfunctions(expect_shutdown=False, print_error=False):
    out = None
    try:
        wait_for_port_open(config.LOCAL_PORT_STEPFUNCTIONS, sleep_time=2)
        endpoint_url = f"http://127.0.0.1:{config.LOCAL_PORT_STEPFUNCTIONS}"
        out = aws_stack.connect_to_service(
            service_name="stepfunctions", endpoint_url=endpoint_url
        ).list_state_machines()
    except Exception:
        if print_error:
            LOG.exception("StepFunctions health check failed")

    if expect_shutdown:
        assert out is None
    else:
        assert out and isinstance(out.get("stateMachines"), list)


def restart_stepfunctions():
    if not PROCESS_THREAD:
        return
    LOG.debug("Restarting StepFunctions process ...")
    PROCESS_THREAD.stop()
    start_stepfunctions(asynchronous=True)
