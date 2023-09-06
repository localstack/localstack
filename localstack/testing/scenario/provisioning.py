import json
import logging
from contextlib import contextmanager
from typing import TYPE_CHECKING, Callable, Optional

import aws_cdk as cdk
from typing_extensions import Self

from localstack.testing.aws.util import is_aws_cloud

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

from localstack.aws.api.cloudformation import Capability
from localstack.aws.connect import ServiceLevelClientFactory

LOG = logging.getLogger(__name__)
CDK_BOOTSTRAP_PARAM = "/cdk-bootstrap/hnb659fds/version"
WAITER_CONFIG_AWS = {"Delay": 10, "MaxAttempts": 1000}
WAITER_CONFIG_LS = {"Delay": 1, "MaxAttempts": 500}


def cleanup_s3_bucket(s3_client: "S3Client", bucket_name: str, delete_bucket: bool = False):
    LOG.debug(f"Cleaning provisioned S3 Bucket {bucket_name}")
    try:
        objs = s3_client.list_objects_v2(Bucket=bucket_name)
        objs_num = objs["KeyCount"]
        if objs_num > 0:
            LOG.debug(f"Deleting {objs_num} objects from {bucket_name}")
            obj_keys = [{"Key": o["Key"]} for o in objs["Contents"]]
            s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": obj_keys})
        if delete_bucket:
            s3_client.delete_bucket(Bucket=bucket_name)
    except Exception:
        LOG.warning(
            f"Failed to clean provisioned S3 Bucket {bucket_name}",
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )


class InfraProvisioner:
    """
    TODO: explore adding support for updates during tests
    TODO: explore asset handling
    """

    cloudformation_stacks: dict[str, dict]
    custom_cleanup_steps: list[Callable]
    custom_setup_steps: list[Callable]
    skipped_provisioning: bool = False

    def __init__(self, aws_client: ServiceLevelClientFactory):
        self.cloudformation_stacks = {}
        self.custom_cleanup_steps = []
        self.custom_setup_steps = []
        self.aws_client = aws_client

    @contextmanager
    def provisioner(self, skip_teardown: bool = False) -> Self:
        try:
            self.provision()
            yield self
        finally:
            if not skip_teardown:
                self.teardown()
            else:
                LOG.info("Skipping teardown. Resources and stacks are not deleted.")

    def provision(self):
        if all(
            self._is_stack_deployed(stack_name, stack)
            for stack_name, stack in self.cloudformation_stacks.items()
        ):
            # TODO it's currently all or nothing -> deploying one new stack will most likely fail
            LOG.info("All stacks are already deployed. Skipping the provisioning.")
            self.skipped_provisioning = True
            return

        self.run_manual_setup_tasks()
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
                StackName=stack_name,
                WaiterConfig=WAITER_CONFIG_AWS if is_aws_cloud() else WAITER_CONFIG_LS,
            )
            describe_stack = self.aws_client.cloudformation.describe_stacks(StackName=stack_name)
            outputs = describe_stack["Stacks"][0].get("Outputs", {})
            stack["Outputs"] = {o["OutputKey"]: o["OutputValue"] for o in outputs}

            if stack["AutoCleanS3"]:
                stack_resources = self.aws_client.cloudformation.describe_stack_resources(
                    StackName=stack_name
                )["StackResources"]
                s3_buckets = [
                    r["PhysicalResourceId"]
                    for r in stack_resources
                    if r["ResourceType"] == "AWS::S3::Bucket"
                ]

                for s3_bucket in s3_buckets:
                    self.custom_cleanup_steps.append(
                        lambda: cleanup_s3_bucket(self.aws_client.s3, s3_bucket)
                    )

    def get_stack_outputs(self, stack_name: str):
        return self.cloudformation_stacks.get(stack_name, {}).get("Outputs", {})

    def teardown(self):
        for fn in self.custom_cleanup_steps:
            fn()
        for stack_name, stack in self.cloudformation_stacks.items():
            self.aws_client.cloudformation.delete_stack(StackName=stack_name)
            self.aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                StackName=stack_name,
                WaiterConfig=WAITER_CONFIG_AWS if is_aws_cloud() else WAITER_CONFIG_LS,
            )
        # TODO log-groups created by lambda are not automatically cleaned up by CDK

        if not is_aws_cloud():
            # TODO proper handling of ssm parameter
            try:
                self.aws_client.ssm.delete_parameter(Name=CDK_BOOTSTRAP_PARAM)
            except Exception:
                pass

    def add_cdk_stack(self, cdk_stack: cdk.Stack, autoclean_buckets: Optional[bool] = True):
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
            "AutoCleanS3": autoclean_buckets,
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
            self.aws_client.ssm.get_parameter(Name=CDK_BOOTSTRAP_PARAM)
        except self.aws_client.ssm.exceptions.ParameterNotFound:
            self.aws_client.ssm.put_parameter(Name=CDK_BOOTSTRAP_PARAM, Type="String", Value="10")

    def add_custom_teardown(self, cleanup_task: Callable):
        self.custom_cleanup_steps.append(cleanup_task)

    def add_custom_setup_provisioning_step(self, setup_task: Callable):
        self.custom_setup_steps.append(setup_task)

    def run_manual_setup_tasks(self):
        for fn in self.custom_setup_steps:
            fn()

    def _is_stack_deployed(self, stack_name: str, stack: dict) -> bool:
        try:
            describe_stack = self.aws_client.cloudformation.describe_stacks(StackName=stack_name)
            if outputs := describe_stack["Stacks"][0].get("Outputs"):
                stack["Outputs"] = {o["OutputKey"]: o["OutputValue"] for o in outputs}
        except Exception:
            return False
        # TODO should we try to run teardown first, if the status is not "CREATE_COMPLETE"?
        return describe_stack["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"
