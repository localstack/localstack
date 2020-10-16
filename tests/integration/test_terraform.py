import os
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import run

BUCKET_NAME = 'tf-bucket'


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
        run('cd %s; terraform destroy -auto-approve' % (base_dir))

    def test_bucket_exists(self):
        s3_client = aws_stack.connect_to_service('s3')
        response = s3_client.head_bucket(Bucket=BUCKET_NAME)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
