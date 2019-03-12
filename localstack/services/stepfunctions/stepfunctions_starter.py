import logging
from localstack import config
from localstack.services import install
from localstack.utils.aws import aws_stack
from localstack.constants import DEFAULT_PORT_STEPFUNCTIONS_BACKEND, TEST_AWS_ACCOUNT_ID, DEFAULT_REGION
from localstack.services.infra import get_service_protocol, start_proxy_for_service, do_run

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = '256m'


def start_stepfunctions(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_STEPFUNCTIONS
    install.install_stepfunctions_local()
    backend_port = DEFAULT_PORT_STEPFUNCTIONS_BACKEND
    # TODO: local port is currently hard coded in Step Functions Local :/
    backend_port = 8083
    lambda_endpoint = aws_stack.get_local_service_url('lambda')
    dynamodb_endpoint = aws_stack.get_local_service_url('dynamodb')
    sns_endpoint = aws_stack.get_local_service_url('sns')
    sqs_endpoint = aws_stack.get_local_service_url('sqs')
    cmd = ('cd %s; java -Dcom.amazonaws.sdk.disableCertChecking -Xmx%s -jar StepFunctionsLocal.jar '
           '--lambda-endpoint %s --dynamodb-endpoint %s --sns-endpoint %s '
           '--sqs-endpoint %s --aws-region %s --aws-account %s') % (
        install.INSTALL_DIR_STEPFUNCTIONS, MAX_HEAP_SIZE, lambda_endpoint, dynamodb_endpoint,
        sns_endpoint, sqs_endpoint, DEFAULT_REGION, TEST_AWS_ACCOUNT_ID)
    print('Starting mock StepFunctions (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('stepfunctions', port, backend_port, update_listener)
    return do_run(cmd, asynchronous)
