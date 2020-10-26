import os
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import run

BUCKET_NAME = 'tf-bucket'
QUEUE_NAME = 'tf-queue'

# lambda Testing Variables
LAMBDA_NAME = 'tf-lambda'
LAMBDA_HANDLER = 'DotNetCore2::DotNetCore2.Lambda.Function::SimpleFunctionHandler'
LAMBDA_RUNTIME = 'dotnetcore2.0'
LAMBDA_ROLE = 'arn:aws:iam::000000000000:role/iam_for_lambda'


class TestTerraform(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        base_dir = os.path.join(os.path.dirname(__file__), 'terraform')
        if not os.path.exists(os.path.join(base_dir, '.terraform')):
            run('cd %s; terraform init -input=false' % base_dir)
        run('cd %s; terraform plan -out=tfplan -input=false' % (base_dir))
        run('cd %s; terraform apply -input=false tfplan' % (base_dir))

    @classmethod
    def tearDownClass(cls):
        base_dir = os.path.join(os.path.dirname(__file__), 'terraform')
        run('cd %s; terraform destroy -auto-approve;' % (base_dir))

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
        # mytestresource = {
        #     'pathPart': 'mytestresource',
        #     'path': '/mytestresource',
        #     'resourceMethods': {
        #         'OPTIONS': {
        #             'httpMethod': 'OPTIONS',
        #             'authorizationType': 'NONE',
        #             'methodIntegration': {
        #                 'type': 'MOCK',
        #                 'httpMethod': 'OPTIONS',
        #                 'passthroughBehavior': 'WHEN_NO_MATCH',
        #             }
        #         },
        #         'GET': {
        #             'httpMethod': 'GET',
        #             'authorizationType': 'NONE',
        #             'apiKeyRequired': False,
        #             'methodIntegration': {
        #                 'type': 'MOCK',
        #                 'httpMethod': 'POST',
        #                 'requestTemplates': {
        #                     'application/xml': '  {\n     "body" : $input.json(\'$\')\n  }\n'
        #                 },
        #                 'passthroughBehavior': 'WHEN_NO_MATCH',
        #             }
        #         }
        #     }
        # }

        # mytestresource1 = {
        #     'pathPart': 'mytestresource1',
        #     'path': '/mytestresource1',
        #     'resourceMethods': {
        #         'GET': {
        #             'httpMethod': 'GET',
        #             'authorizationType': 'NONE',
        #             'apiKeyRequired': False,
        #             'methodIntegration': {
        #                 'type': 'AWS_PROXY',
        #                 'httpMethod': 'POST',
        #                 'uri': 'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/' +
        #                        'arn:aws:lambda:us-east-1:000000000000:function:tf-lambda/invocations',
        #                 'passthroughBehavior': 'WHEN_NO_MATCH',
        #             }
        #         },
        #         'OPTIONS': {
        #             'httpMethod': 'OPTIONS',
        #             'authorizationType': 'NONE',
        #             'apiKeyRequired': False,
        #             'methodIntegration': {
        #                 'type': 'MOCK',
        #                 'httpMethod': 'OPTIONS',
        #                 'passthroughBehavior': 'WHEN_NO_MATCH',
        #             }
        #         }
        #     }
        # }
        print('starting')
        apigateway_client = aws_stack.connect_to_service('apigateway')
        print('starting1')
        rest_apis = apigateway_client.get_rest_apis()
        print('starting2')
        for rest_api in rest_apis['items']:
            if rest_api['name'] == 'test-tf-apigateway':
                rest_id = rest_api['id']
                continue
        print('starting4')
        resources = apigateway_client.get_resources(restApiId=rest_id)['items']
        self.assertEqual(len(resources), 3)
        print(resources)
        res1 = [r for r in resources if r['pathPart'] == 'mytestresource']
        self.assertTrue(res1)
        print(res1[0]['path'])
        print(res1[1]['path'])
        print(res1[2]['path'])
        self.assertEqual(res1[1]['path'], '/mytestresource')
