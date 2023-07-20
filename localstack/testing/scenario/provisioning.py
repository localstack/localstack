import json

import aws_cdk as cdk

from localstack.aws.api.cloudformation import Capability
from localstack.aws.connect import ServiceLevelClientFactory


class InfraProvisioner:
    """
    TODO: explore adding support for updates during tests
    TODO: explore asset handling
    """

    cloudformation_stacks: dict[str, dict]

    def __init__(self, aws_client: ServiceLevelClientFactory):
        self.cloudformation_stacks = {}
        self.aws_client = aws_client

    def provision(self):
        self.bootstrap_cdk()
        for stack_name, stack in self.cloudformation_stacks.items():
            self.aws_client.cloudformation.create_stack(
                StackName=stack_name,
                TemplateBody=stack["Template"],
                Capabilities=[
                    Capability.CAPABILITY_AUTO_EXPAND,
                    Capability.CAPABILITY_IAM,
                    Capability.CAPABILITY_NAMED_IAM,
                ],
            )
            self.aws_client.cloudformation.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 1}
            )
            describe_stack = self.aws_client.cloudformation.describe_stacks(StackName=stack_name)
            outputs = describe_stack["Stacks"][0]["Outputs"]
            stack["Outputs"] = {o["OutputKey"]: o["OutputValue"] for o in outputs}

    def get_stack_outputs(self, stack_name: str):
        return self.cloudformation_stacks[stack_name]["Outputs"]

    def teardown(self):
        for stack_name, stack in self.cloudformation_stacks.items():
            self.aws_client.cloudformation.delete_stack(StackName=stack_name)
            self.aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 1}
            )

    def add_cdk_stack(self, cdk_stack: cdk.Stack):
        """
        1. check if synthesized templates exists
        2. if no templates exists OR forced update enabled => synth cdk.App into CloudFormation template and save it
        3. deploy templates / assets / etc.
        4. register teardown
        """
        template_json = cdk.assertions.Template.from_stack(cdk_stack).to_json()
        template = json.dumps(template_json)
        self.cloudformation_stacks[cdk_stack.stack_name] = {
            "StackName": cdk_stack.stack_name,
            "Template": template,
        }

    def add_cdk_app(self, cdk_app: cdk.App):
        """
        !!! WORK IN PROGRESS !!!

        1. check if synthesized templates exists
        2. if no templates exists OR forced update enabled => synth cdk.App into CloudFormation template and save it
        3. deploy templates / assets / etc.
        4. register teardown
        """
        # cloud_assembly = cdk_app.synth()
        ...

    def bootstrap_cdk(self):
        # TODO: add proper bootstrap template to deploy here if there's no parameter yet
        try:
            self.aws_client.ssm.get_parameter(Name="/cdk-bootstrap/hnb659fds/version")
        except self.aws_client.ssm.exceptions.ParameterNotFound:
            self.aws_client.ssm.put_parameter(
                Name="/cdk-bootstrap/hnb659fds/version", Type="String", Value="10"
            )
