"""
Notes

We assume order of test declaration => test execution (pytest default)
Need to be mindful of state drift
execution of tests should never be split inside classes (shouldn't be the case anyway right now)



Ideas:

* custom state reset / state validators between tests?


Todos:

* warn if a CDK construct is used that would create an asset
* make the InfraProvisioner into a fixture and add a pytest hook implementation

"""
import pytest
import aws_cdk as cdk

class BotoDeployment:

    def setup(self):
        ...

    def teardown(self):
        ...



class InfraProvisioner:

    def add_cdk_step(self, cdk_app: cdk.App):
        """
        1. check if synthesized templates exists
        2. if no templates exists OR forced update enabled => synth cdk.App into CloudFormation template and save it
        3. deploy templates / assets / etc.
        4. register teardown
        """
        # cdk
        # ca = cdk.assertions.Template.from_stack()


class TestSomeScenario:
    # ... infra setup
    # ... CloudFormation stack(s) + Other manual infra setup (e.g. via boto calls)

    @pytest.fixture(scope="class", autouse=True)
    def define_infrastructure(self, aws_client):
        # CDK setup
        app = cdk.App()
        stack1 = cdk.Stack(app, "StackA")
        stack2 = cdk.Stack(app, "StackB")
        queue = cdk.aws_sqs.Queue(stack, "Queue")

        def clean_s3_bucket():
            ...

        provisioner = InfraProvisioner()
        # will be cleaned up in reverse order
        provisioner.add_boto_step(setup_func, teardown_func)
        provisioner.add_cdk_step(app, "my-first-scenario-1")
        provisioner.add_boto_step(teardown=clean_s3_bucket)

        provisioner.provision()
        yield provisioner
        provisioner.cleanup()


    # ... state initialization
    def initialize_state(self, aws_client):
        """
        Initialize application state
        """
        ...
        table_name = "...."
        aws_client.dynamodb.put_items(TableName=table_name, ....)


    ### TESTS

    def test_infra_state(self):
        ...

    def test_scenario1(self, aws_client):
        sqs_client = aws_client.sqs
        sqs_client.send_message(QueueUrl="...", MessageBody="...")

        logs = aws_client.logs.filter_log_events(...)
        assert logs # something

    def test_scenario2(self):
        ...

