import os
import unittest
import threading
from localstack.utils.aws import aws_stack
from localstack.utils.common import run, start_worker_thread, is_command_available, rm_rf

BUCKET_NAME = 'tf-bucket'
QUEUE_NAME = 'tf-queue'

# lambda Testing Variables
LAMBDA_NAME = 'tf-lambda'
LAMBDA_HANDLER = 'DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler'
LAMBDA_RUNTIME = 'dotnetcore2.0'
LAMBDA_ROLE = 'arn:aws:iam::000000000000:role/iam_for_lambda'

INIT_LOCK = threading.RLock()


class TestTerraform(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with(INIT_LOCK):
            run('cd %s; terraform apply -input=false tfplan' % (cls.get_base_dir()))

    @classmethod
    def tearDownClass(cls):
        run('cd %s; terraform destroy -auto-approve' % (cls.get_base_dir()))

    @classmethod
    def init_async(cls):
        if not is_command_available('terraform'):
            return

        def _run(*args):
            with(INIT_LOCK):
                base_dir = cls.get_base_dir()
                if not os.path.exists(os.path.join(base_dir, '.terraform', 'plugins')):
                    run('cd %s; terraform init -input=false' % base_dir)
                # remove any cache files from previous runs
                for tf_file in ['tfplan', 'terraform.tfstate', 'terraform.tfstate.backup']:
                    rm_rf(os.path.join(base_dir, tf_file))
                # create TF plan
                run('cd %s; terraform plan -out=tfplan -input=false' % base_dir)
        start_worker_thread(_run)

    @classmethod
    def get_base_dir(*args):
        return os.path.join(os.path.dirname(__file__), 'terraform')

    def test_bucket_exists(self):
        s3_client = aws_stack.connect_to_service('s3')

        response = s3_client.head_bucket(Bucket=BUCKET_NAME)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        cors = {
            'AllowedHeaders': ['*'],
            'AllowedMethods': ['GET', 'PUT', 'POST'],
            'AllowedOrigins': ['*'],
            'ExposeHeaders': ['ETag', 'x-amz-version-id'],
            'MaxAgeSeconds': 3000
        }

        response = s3_client.get_bucket_cors(Bucket=BUCKET_NAME)
        self.assertEqual(response['CORSRules'][0], cors)

        response = s3_client.get_bucket_versioning(Bucket=BUCKET_NAME)
        self.assertEqual(response['Status'], 'Enabled')

    def test_sqs(self):
        sqs_client = aws_stack.connect_to_service('sqs')
        queue_url = sqs_client.get_queue_url(QueueName=QUEUE_NAME)['QueueUrl']
        response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])

        self.assertEqual(response['Attributes']['DelaySeconds'], '90')
        self.assertEqual(response['Attributes']['MaximumMessageSize'], '2048')
        self.assertEqual(response['Attributes']['MessageRetentionPeriod'], '86400')
        self.assertEqual(response['Attributes']['ReceiveMessageWaitTimeSeconds'], '10')

    def test_lambda(self):
        lambda_client = aws_stack.connect_to_service('lambda')
        response = lambda_client.get_function(FunctionName=LAMBDA_NAME)
        self.assertEqual(response['Configuration']['FunctionName'], LAMBDA_NAME)
        self.assertEqual(response['Configuration']['Handler'], LAMBDA_HANDLER)
        self.assertEqual(response['Configuration']['Runtime'], LAMBDA_RUNTIME)
        self.assertEqual(response['Configuration']['Role'], LAMBDA_ROLE)

    def test_apigateway(self):
        apigateway_client = aws_stack.connect_to_service('apigateway')
        rest_apis = apigateway_client.get_rest_apis()

        rest_id = None
        for rest_api in rest_apis['items']:
            if rest_api['name'] == 'test-tf-apigateway':
                rest_id = rest_api['id']
                break

        self.assertTrue(rest_id)
        resources = apigateway_client.get_resources(restApiId=rest_id)['items']

        # We always have 1 default root resource (with path "/")
        self.assertEqual(len(resources), 3)

        res1 = [r for r in resources if r.get('pathPart') == 'mytestresource']
        self.assertTrue(res1)
        self.assertEqual(res1[0]['path'], '/mytestresource')
        self.assertEqual(len(res1[0]['resourceMethods']), 2)
        self.assertEqual(res1[0]['resourceMethods']['GET']['methodIntegration']['type'], 'MOCK')

        res2 = [r for r in resources if r.get('pathPart') == 'mytestresource1']
        self.assertTrue(res2)
        self.assertEqual(res2[0]['path'], '/mytestresource1')
        self.assertEqual(len(res2[0]['resourceMethods']), 2)
        self.assertEqual(res2[0]['resourceMethods']['GET']['methodIntegration']['type'], 'AWS_PROXY')
        self.assertTrue(res2[0]['resourceMethods']['GET']['methodIntegration']['uri'])

    def test_route53(self):
        route53 = aws_stack.connect_to_service('route53')

        response = route53.create_hosted_zone(Name='zone123', CallerReference='ref123')
        self.assertEqual(201, response['ResponseMetadata']['HTTPStatusCode'])
        change_id = response.get('ChangeInfo', {}).get('Id', 'change123')

        response = route53.get_change(Id=change_id)
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

    def test_acm(self):
        acm = aws_stack.connect_to_service('acm')

        certs = acm.list_certificates()['CertificateSummaryList']
        certs = [c for c in certs if c.get('DomainName') == 'example.com']
        self.assertEqual(len(certs), 1)

    def test_apigateway_escaped_policy(self):
        apigateway_client = aws_stack.connect_to_service('apigateway')
        rest_apis = apigateway_client.get_rest_apis()

        service_apis = []

        for rest_api in rest_apis['items']:
            if rest_api['name'] == 'service_api':
                service_apis.append(rest_api)

        self.assertEqual(len(service_apis), 1)
