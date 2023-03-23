import json
import os.path

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.utils.strings import short_uid, to_str
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO


TEST_LAMBDA_PYTHON_STATE = os.path.join(os.path.dirname(__file__), "functions/lambda_get_state.py")

def test_single_fn(lambda_client, create_lambda_function, logs_client):
    """ assumption: single static python3.9 worker """
    function_name = f"test-fn-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )
    lambda_client.invoke(FunctionName=function_name, Payload=json.dumps({"hello": "worker"}))

    #
    # lambda_client.invoke(FunctionName=function_name, InvocationType="Event")# TODO: wait
    # lambda_client.invoke(FunctionName=function_name, InvocationType="Event")# TODO: wait
    # lambda_client.invoke(FunctionName=function_name, InvocationType="Event")  # TODO: wait
    # # wait until 4 invocations
    #
    # # static config -> *global* concurrency limit (kinda like the setting but global not regional)
    # lambda_client.invoke(FunctionName=function_name, InvocationType="Event")  # TODO: wait
    # with pytest.raises(lambda_client.exceptions.TooManyRequestsException) as e:
    #     lambda_client.invoke(FunctionName=function_name, InvocationType="RequestResponse")

    # failures
    # lambda_client.put_provisioned_concurrency_config()
    # lambda_client.delete_provisioned_concurrency_config()


# this test requires explicit knowledge about how the worker behaves
@pytest.mark.whitebox
def test_multiple_fn(lambda_client, create_lambda_function, logs_client):
    """ assumption: single static python3.9 worker """
    fn1 = f"test-fn-{short_uid()}"

    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_STATE,
        func_name=fn1,
        runtime=Runtime.python3_9,
    )
    fn2 = f"test-fn-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_STATE,
        func_name=fn2,
        runtime=Runtime.python3_9,
    )
    result1_premod = lambda_client.invoke(FunctionName=fn1, Payload=json.dumps({"action": "check"})) # get fs state (verify clean)
    result1 = to_str(result1_premod['Payload'].read())
    lambda_client.invoke(FunctionName=fn1, Payload=json.dumps({"action": "modify"})) # modify fs
    result1_postmod = lambda_client.invoke(FunctionName=fn1, Payload=json.dumps({"action": "check"})) # get fs state (verify modification)
    result2 = to_str(result1_postmod['Payload'].read())

    result2_premod = lambda_client.invoke(FunctionName=fn2) # get fs state (verify clean)
    lambda_client.invoke(FunctionName=fn2) # modify fs
    result2_postmod = lambda_client.invoke(FunctionName=fn2) # get fs state (verify modification)
    #
    # lambda_client.invoke(FunctionName=fn1) # get fs state (verify clean)
    # lambda_client.invoke(FunctionName=fn1) # modify fs
    # lambda_client.invoke(FunctionName=fn1) # get fs state (verify modification)

    print("done")




def test_blocking_next(lambda_client, create_lambda_function, logs_client):
    fn1 = f"test-fn-{short_uid()}"

    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=fn1,
        runtime=Runtime.python3_9,
    )

    result1_premod = lambda_client.invoke(FunctionName=fn1, Payload=json.dumps({"action": "check"})) # get fs state (verify clean)
    result1 = to_str(result1_premod['Payload'].read())
    print("done")


def test_unschedulable_fn(lambda_client, create_lambda_function, logs_client):
    fn1 = f"test-fn-{short_uid()}"

    # TODO: where should we fail? invoke or earlier? (e.g. state)
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=fn1,
        runtime=Runtime.python3_8,
    )
    lambda_client.invoke(FunctionName=fn1)
