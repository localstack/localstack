import logging

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import install
from localstack.services.infra import do_run, log_startup_message, start_proxy_for_service
from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = "256m"


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
    return do_run(cmd, asynchronous)
