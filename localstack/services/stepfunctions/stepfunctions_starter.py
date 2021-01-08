import logging
from localstack import config
from localstack.services import install
from localstack.utils.aws import aws_stack
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.infra import edge_ports_info, start_proxy_for_service, do_run

LOG = logging.getLogger(__name__)

# max heap size allocated for the Java process
MAX_HEAP_SIZE = '256m'


def get_command(backend_port):
    dynamodb_endpoint = aws_stack.get_local_service_url('dynamodb')
    sns_endpoint = aws_stack.get_local_service_url('sns')
    sqs_endpoint = aws_stack.get_local_service_url('sqs')
    sfn_endpoint = aws_stack.get_local_service_url('stepfunctions')
    cmd = ('cd %s; PORT=%s java -Dcom.amazonaws.sdk.disableCertChecking -Xmx%s -jar StepFunctionsLocal.jar '
           '--dynamodb-endpoint %s --sns-endpoint %s '
           '--sqs-endpoint %s --aws-region %s --aws-account %s --step-functions-endpoint %s') % (
        install.INSTALL_DIR_STEPFUNCTIONS, backend_port, MAX_HEAP_SIZE, dynamodb_endpoint,
        sns_endpoint, sqs_endpoint, aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, sfn_endpoint)
    if config.STEPFUNCTIONS_LAMBDA_ENDPOINT.lower() != 'default':
        lambda_endpoint = config.STEPFUNCTIONS_LAMBDA_ENDPOINT or aws_stack.get_local_service_url('lambda')
        cmd += (' --lambda-endpoint %s') % (lambda_endpoint)
    return cmd


def start_stepfunctions(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_STEPFUNCTIONS
    backend_port = config.LOCAL_PORT_STEPFUNCTIONS
    install.install_stepfunctions_local()
    cmd = get_command(backend_port)
    print('Starting mock StepFunctions service on %s ...' % edge_ports_info())
    start_proxy_for_service('stepfunctions', port, backend_port, update_listener)
    return do_run(cmd, asynchronous)
