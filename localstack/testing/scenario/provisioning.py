import json

import aws_cdk as cdk

from localstack.aws.connect import ServiceLevelClientFactory


class InfraProvisioner:
    def __init__(self, aws_client: ServiceLevelClientFactory):
        self.cloudformation_stacks = []
        self.aws_client = aws_client

    def provision(self):
        self.bootstrap_cdk()
        for stack in self.cloudformation_stacks:
            create_response = self.aws_client.cloudformation.create_stack(
                StackName=stack["StackName"], TemplateBody=stack["Template"]
            )
            self.aws_client.cloudformation.get_waiter("stack_create_complete").wait(
                StackName=stack["StackName"]
            )

    def teardown(self):
        for stack in self.cloudformation_stacks:
            self.aws_client.cloudformation.delete_stack(StackName=stack["StackName"])
            self.aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                StackName=stack["StackName"]
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
        self.cloudformation_stacks.append({"StackName": cdk_stack.stack_name, "Template": template})

    def add_cdk_app(self, cdk_app: cdk.App):  # TODO: make this take a cdk.App
        """
        1. check if synthesized templates exists
        2. if no templates exists OR forced update enabled => synth cdk.App into CloudFormation template and save it
        3. deploy templates / assets / etc.
        4. register teardown
        """
        cloud_assembly = cdk_app.synth()
        print("got assembly")

    def bootstrap_cdk(self):
        # TODO: add proper bootstrap template to deploy here if there's no parameter yet
        self.aws_client.ssm.put_parameter(
            Name="/cdk-bootstrap/hnb659fds/version", Type="String", Value="10"
        )
