import os
import json
import time
from io import BytesIO
from localstack.constants import LOCALSTACK_ROOT_FOLDER, LOCALSTACK_MAVEN_VERSION
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, load_file, to_str, mkdir, download
from localstack.services.awslambda import lambda_api, lambda_executors
from localstack.services.awslambda.lambda_api import (LAMBDA_RUNTIME_NODEJS,
    LAMBDA_RUNTIME_PYTHON27, LAMBDA_RUNTIME_PYTHON36, LAMBDA_RUNTIME_JAVA8, use_docker)

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py')
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_python3.py')
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.js')
TEST_LAMBDA_JAVA = os.path.join(LOCALSTACK_ROOT_FOLDER, 'localstack', 'infra', 'localstack-utils-tests.jar')
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_environment.py')

TEST_LAMBDA_NAME_PY = 'test_lambda_py'
TEST_LAMBDA_NAME_PY3 = 'test_lambda_py3'
TEST_LAMBDA_NAME_JS = 'test_lambda_js'
TEST_LAMBDA_NAME_JAVA = 'test_lambda_java'
TEST_LAMBDA_NAME_JAVA_STREAM = 'test_lambda_java_stream'
TEST_LAMBDA_NAME_JAVA_SERIALIZABLE = 'test_lambda_java_serializable'
TEST_LAMBDA_NAME_ENV = 'test_lambda_env'

TEST_LAMBDA_JAR_URL = ('https://repo.maven.apache.org/maven2/cloud/localstack/' +
    'localstack-utils/{version}/localstack-utils-{version}-tests.jar').format(version=LOCALSTACK_MAVEN_VERSION)

TEST_LAMBDA_LIBS = ['localstack', 'localstack_client', 'requests', 'psutil', 'urllib3', 'chardet', 'certifi', 'idna']


def test_upload_lambda_from_s3():

    s3_client = aws_stack.connect_to_service('s3')
    lambda_client = aws_stack.connect_to_service('lambda')

    lambda_name = 'test_lambda_%s' % short_uid()
    bucket_name = 'test_bucket_lambda'
    bucket_key = 'test_lambda.zip'

    # upload zip file to S3
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.upload_fileobj(BytesIO(zip_file), bucket_name, bucket_key)

    # create lambda function
    lambda_client.create_function(
        FunctionName=lambda_name, Handler='handler.handler',
        Runtime=lambda_api.LAMBDA_RUNTIME_PYTHON27, Role='r1',
        Code={
            'S3Bucket': bucket_name,
            'S3Key': bucket_key
        }
    )

    # invoke lambda function
    data_before = b'{"foo": "bar"}'
    result = lambda_client.invoke(FunctionName=lambda_name, Payload=data_before)
    data_after = result['Payload'].read()
    assert json.loads(to_str(data_before)) == json.loads(to_str(data_after))


def test_lambda_runtimes():

    lambda_client = aws_stack.connect_to_service('lambda')

    # deploy and invoke lambda - Python 2.7
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_PY,
        zip_file=zip_file, runtime=LAMBDA_RUNTIME_PYTHON27)
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_PY, Payload=b'{}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert to_str(result_data).strip() == '{}'

    if use_docker():
        # deploy and invoke lambda - Python 3.6
        zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON3), get_content=True,
            libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON36)
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_PY3,
            zip_file=zip_file, runtime=LAMBDA_RUNTIME_PYTHON36)
        result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_PY3, Payload=b'{}')
        assert result['StatusCode'] == 200
        result_data = result['Payload'].read()
        assert to_str(result_data).strip() == '{}'

    # deploy and invoke lambda - Java
    if not os.path.exists(TEST_LAMBDA_JAVA):
        mkdir(os.path.dirname(TEST_LAMBDA_JAVA))
        download(TEST_LAMBDA_JAR_URL, TEST_LAMBDA_JAVA)
    zip_file = testutil.create_zip_file(TEST_LAMBDA_JAVA, get_content=True)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_JAVA, zip_file=zip_file,
        runtime=LAMBDA_RUNTIME_JAVA8, handler='cloud.localstack.sample.LambdaHandler')
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JAVA, Payload=b'{}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert 'LinkedHashMap' in to_str(result_data)

    # test SNSEvent
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JAVA, InvocationType='Event',
                                  Payload=b'{"Records": [{"Sns": {"Message": "{}"}}]}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert json.loads(to_str(result_data)) == {'async': 'True'}

    # test KinesisEvent
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JAVA,
                                  Payload=b'{"Records": [{"Kinesis": {"Data": "data", "PartitionKey": "partition"}}]}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert 'KinesisEvent' in to_str(result_data)

    # deploy and invoke lambda - Java with stream handler
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_JAVA_STREAM, zip_file=zip_file,
        runtime=LAMBDA_RUNTIME_JAVA8, handler='cloud.localstack.sample.LambdaStreamHandler')
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JAVA_STREAM, Payload=b'{}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert to_str(result_data).strip() == '{}'

    # deploy and invoke lambda - Java with serializable input object
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_JAVA_SERIALIZABLE, zip_file=zip_file,
        runtime=LAMBDA_RUNTIME_JAVA8, handler='cloud.localstack.sample.SerializedInputLambdaHandler')
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JAVA_SERIALIZABLE,
                                  Payload=b'{"bucket": "test_bucket", "key": "test_key"}')
    assert result['StatusCode'] == 200
    result_data = result['Payload'].read()
    assert json.loads(to_str(result_data)) == {'validated': True, 'bucket': 'test_bucket', 'key': 'test_key'}

    if use_docker():
        # deploy and invoke lambda - Node.js
        zip_file = testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True)
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_JS,
            zip_file=zip_file, handler='lambda_integration.handler', runtime=LAMBDA_RUNTIME_NODEJS)
        result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_JS, Payload=b'{}')
        assert result['StatusCode'] == 200
        result_data = result['Payload'].read()
        assert to_str(result_data).strip() == '{}'


def test_lambda_environment():

    lambda_client = aws_stack.connect_to_service('lambda')

    # deploy and invoke lambda without Docker
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_ENV), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_ENV,
        zip_file=zip_file, runtime=LAMBDA_RUNTIME_PYTHON27, envvars={'Hello': 'World'})
    result = lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_ENV, Payload=b'{}')
    assert result['StatusCode'] == 200
    result_data = result['Payload']
    assert json.load(result_data) == {'Hello': 'World'}


def test_prime_and_destroy_containers():

    # run these tests only for the "reuse containers" Lambda executor
    if not isinstance(lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers):
        return

    executor = lambda_api.LAMBDA_EXECUTOR
    func_name = 'test_prime_and_destroy_containers'

    # create a new lambda
    lambda_client = aws_stack.connect_to_service('lambda')

    func_arn = lambda_api.func_arn(func_name)

    # make sure existing containers are gone
    executor.cleanup()
    assert len(executor.get_all_container_names()) == 0

    # deploy and invoke lambda without Docker
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_ENV), get_content=True,
                                              libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=func_name, zip_file=zip_file,
                                    runtime=LAMBDA_RUNTIME_PYTHON27, envvars={'Hello': 'World'})

    assert len(executor.get_all_container_names()) == 0

    assert executor.function_invoke_times == {}

    # invoke a few times.
    durations = []
    num_iterations = 3

    for i in range(0, num_iterations + 1):
        prev_invoke_time = None
        if i > 0:
            prev_invoke_time = executor.function_invoke_times[func_arn]

        start_time = time.time()
        lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
        duration = time.time() - start_time

        assert len(executor.get_all_container_names()) == 1

        # ensure the last invoke time is being updated properly.
        if i > 0:
            assert executor.function_invoke_times[func_arn] > prev_invoke_time
        else:
            assert executor.function_invoke_times[func_arn] > 0

        durations.append(duration)

    # the first call would have created the container. subsequent calls would reuse and be faster.
    for i in range(1, num_iterations + 1):
        assert durations[i] < durations[0]

    status = executor.get_docker_container_status(func_arn)
    assert status == 1

    executor.cleanup()
    status = executor.get_docker_container_status(func_arn)
    assert status == 0

    assert len(executor.get_all_container_names()) == 0


def test_destroy_idle_containers():

    # run these tests only for the "reuse containers" Lambda executor
    if not isinstance(lambda_api.LAMBDA_EXECUTOR, lambda_executors.LambdaExecutorReuseContainers):
        return

    executor = lambda_api.LAMBDA_EXECUTOR
    func_name = 'test_destroy_idle_containers'

    # create a new lambda
    lambda_client = aws_stack.connect_to_service('lambda')

    func_arn = lambda_api.func_arn(func_name)

    # make sure existing containers are gone
    executor.destroy_existing_docker_containers()
    assert len(executor.get_all_container_names()) == 0

    # deploy and invoke lambda without Docker
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_ENV), get_content=True,
                                              libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=func_name,
                                    zip_file=zip_file, runtime=LAMBDA_RUNTIME_PYTHON27, envvars={'Hello': 'World'})

    assert len(executor.get_all_container_names()) == 0

    lambda_client.invoke(FunctionName=func_name, Payload=b'{}')
    assert len(executor.get_all_container_names()) == 1

    # try to destroy idle containers.
    executor.idle_container_destroyer()
    assert len(executor.get_all_container_names()) == 1

    # simulate an idle container
    executor.function_invoke_times[func_arn] = time.time() - 610
    executor.idle_container_destroyer()
    assert len(executor.get_all_container_names()) == 0
