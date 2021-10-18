import logging

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import install
from localstack.services.infra import do_run, log_startup_message, start_proxy_for_service
from localstack.services.stepfunctions import stepfunctions_listener
from localstack.utils.aws import aws_stack
from localstack.utils.common import wait_for_port_open

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"

# todo: will be replaced with plugin mechanism
PROCESS_THREAD = None


def get_command(backend_port):
    cmd = (
        "cd %s; PORT=%s java -Dcom.amazonaws.sdk.disableCertChecking -Xmx%s -jar StepFunctionsLocal.jar "
        "--aws-region %s --aws-account %s"
    ) % (
        install.INSTALL_DIR_STEPFUNCTIONS,
        backend_port,
        MAX_HEAP_SIZE,
        aws_stack.get_region(),
        TEST_AWS_ACCOUNT_ID,
    )
    if config.STEPFUNCTIONS_LAMBDA_ENDPOINT.lower() != "default":
        lambda_endpoint = config.STEPFUNCTIONS_LAMBDA_ENDPOINT or aws_stack.get_local_service_url(
            "lambda"
        )
        cmd += (" --lambda-endpoint %s") % (lambda_endpoint)
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
        flag = "--%s-endpoint" % service
        if service == "stepfunctions":
            flag = "--step-functions-endpoint"
        elif service == "events":
            flag = "--eventbridge-endpoint"
        elif service in ["athena", "eks"]:
            flag = "--step-functions-%s" % service
        endpoint = aws_stack.get_local_service_url(service)
        cmd += " %s %s" % (flag, endpoint)
    return cmd


def start_stepfunctions(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_STEPFUNCTIONS
    backend_port = config.LOCAL_PORT_STEPFUNCTIONS
    install.install_stepfunctions_local()
    cmd = get_command(backend_port)
    log_startup_message("StepFunctions")
    start_proxy_for_service("stepfunctions", port, backend_port, update_listener)
    global PROCESS_THREAD
    PROCESS_THREAD = do_run(cmd, asynchronous, strip_color=True)
    return PROCESS_THREAD


def check_stepfunctions(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check Kinesis
        wait_for_port_open(config.LOCAL_PORT_STEPFUNCTIONS)
        endpoint_url = f"http://127.0.0.1:{config.LOCAL_PORT_STEPFUNCTIONS}"
        out = aws_stack.connect_to_service(
            service_name="stepfunctions", endpoint_url=endpoint_url
        ).list_state_machines()
    except Exception:
        if print_error:
            LOG.exception("Stepfunctions health check failed")

    if expect_shutdown:
        assert out is None
    else:
        assert out and isinstance(out.get("stateMachines"), list)


def restart_stepfunctions():
    LOG.debug("Restarting StepFunctions process ...")
    PROCESS_THREAD.stop()
    start_stepfunctions(
        asynchronous=True, update_listener=stepfunctions_listener.UPDATE_STEPFUNCTIONS
    )
