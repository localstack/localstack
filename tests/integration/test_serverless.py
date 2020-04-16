import os
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import run


class TestServerless(unittest.TestCase):

    def test_deploy_template(self):
        base_dir = os.path.join(os.path.dirname(__file__), 'serverless')

        if not os.path.exists(os.path.join(base_dir, 'node_modules')):
            # install dependencies
            run('cd %s; npm install' % base_dir)

        # deploy serverless app
        run('cd %s; npm run serverless -- --region=%s' % (base_dir, aws_stack.get_region()))
