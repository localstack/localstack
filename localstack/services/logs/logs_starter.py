import json
import base64
from localstack import config
from localstack.utils.aws import aws_stack
from moto.awslambda import models as lambda_models
from localstack.services.infra import start_moto_server


def patch_lambda():
    def patch_get_function(backend):
        get_function_orig = backend.get_function

        def get_function(*args, **kwargs):
            result = get_function_orig(*args, **kwargs)
            if result:
                return result
            # in case if lambda is not present in moto fall back to
            #  fetching Lambda details from LocalStack API directly
            client = aws_stack.connect_to_service('lambda')
            lambda_name = aws_stack.lambda_function_name(args[0])
            response = client.get_function(FunctionName=lambda_name)
            return response

        return get_function

    def patch_send_log_event(backend):
        send_log_event_orig = backend.send_log_event

        def send_log_event(*args, **kwargs):
            if backend.get_function(args[0]):
                return send_log_event_orig(*args, **kwargs)

            filter_name = args[1]
            log_group_name = args[2]
            log_stream_name = args[3]
            log_events = args[4]

            data = {
                'messageType': 'DATA_MESSAGE',
                'owner': aws_stack.get_account_id(),
                'logGroup': log_group_name,
                'logStream': log_stream_name,
                'subscriptionFilters': [filter_name],
                'logEvents': log_events,
            }

            payload = base64.b64encode(json.dumps(data, separators=(',', ':')).
                                       encode('utf-8')).decode('utf-8')
            event = {'awslogs': {'data': payload}}
            client = aws_stack.connect_to_service('lambda')
            lambda_name = aws_stack.lambda_function_name(args[0])
            client.invoke(FunctionName=lambda_name, Payload=event)

        return send_log_event

    for lambda_backend in lambda_models.lambda_backends.values():
        lambda_backend.get_function = patch_get_function(lambda_backend)
        lambda_backend.send_log_event = patch_send_log_event(lambda_backend)


def start_cloudwatch_logs(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_LOGS
    patch_lambda()
    return start_moto_server('logs', port, name='CloudWatch Logs',
                             asynchronous=asynchronous, update_listener=update_listener)
