import json
import logging
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Callable, ContextManager, Optional

import aws_cdk as cdk
from botocore.exceptions import ClientError, WaiterError

from localstack.config import is_env_true
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest.fixtures import StackDeployError
from localstack.utils.aws.resources import create_s3_bucket
from localstack.utils.files import load_file
from localstack.utils.functions import call_safe
from localstack.utils.strings import short_uid

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

from localstack.aws.api.cloudformation import Capability
from localstack.aws.connect import ServiceLevelClientFactory

LOG = logging.getLogger(__name__)
CDK_BOOTSTRAP_PARAM = "/cdk-bootstrap/hnb659fds/version"
WAITER_CONFIG_AWS = {
    "Delay": 6,
    "MaxAttempts": 600,
}  # total timeout ~1 hour (6 * 600 = 3_600 seconds)
# total timeout ~10 minutes
WAITER_CONFIG_LS = {"Delay": 1, "MaxAttempts": 600}
CFN_MAX_TEMPLATE_SIZE = 51_200


# TODO: move/unify with utils
def cleanup_s3_bucket(s3_client: "S3Client", bucket_name: str, delete_bucket: bool = False):
    LOG.debug("Cleaning provisioned S3 Bucket %s", bucket_name)
    try:
        objs = s3_client.list_objects_v2(Bucket=bucket_name)
        objs_num = objs["KeyCount"]
        if objs_num > 0:
            LOG.debug("Deleting %s objects from bucket_name=%s", objs_num, bucket_name)
            obj_keys = [{"Key": o["Key"]} for o in objs["Contents"]]
            s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": obj_keys})
        if delete_bucket:
            s3_client.delete_bucket(Bucket=bucket_name)
    except Exception:
        LOG.warning(
            "Failed to clean provisioned S3 Bucket bucket_name=%s",
            bucket_name,
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )


# TODO: cross-account tests
# TODO: cross-region references
# TODO: explore asset handling
# TODO: use CDK App as central construct instead of individual stacks
class InfraProvisioner:
    """
    An InfraProvisioner encapsulates logic around the setup and teardown of multiple CDK stacks and custom provisioning steps.
    Use it to set up your infrastructure against which you can then execute individual or multiple integration tests.
    """

    cloudformation_stacks: dict[str, dict]
    custom_cleanup_steps: list[Callable]
    custom_setup_steps: list[Callable]
    aws_client: ServiceLevelClientFactory
    namespace: str
    base_path: str | None
    cdk_app: cdk.App
    persist_output: bool
    force_synth: bool

    def __init__(
        self,
        aws_client: ServiceLevelClientFactory,
        namespace: str,
        base_path: Optional[str] = None,
        force_synth: Optional[bool] = False,
        persist_output: Optional[bool] = False,
    ):
        """
        :param namespace: repo-unique identifier for this CDK app.
            A directory with this name will be created at `tests/aws/cdk_templates/<namespace>/`
        :param base_path: absolute path to `tests/aws/cdk_templates` where synthesized artifacts are stored
        :param aws_client: an aws client factory
        :param force_template_update: set to True to always re-synth the CDK app
        :return: an instantiated CDK InfraProvisioner which can be used to deploy a CDK app
        """
        self.namespace = namespace
        self.base_path = base_path
        self.cloudformation_stacks = {}
        self.custom_cleanup_steps = []
        self.custom_setup_steps = []
        self.aws_client = aws_client
        self.force_synth = force_synth
        self.persist_output = persist_output
        if self.base_path is None:
            self.persist_output = False
        self.cdk_app = cdk.App(default_stack_synthesizer=cdk.BootstraplessSynthesizer())

    def get_asset_bucket(self):
        account = self.aws_client.sts.get_caller_identity()["Account"]
        region = self.aws_client.sts.meta.region_name
        return f"localstack-testing-{account}-{region}"

    @contextmanager
    def provisioner(
        self, skip_deployment: Optional[bool] = False, skip_teardown: Optional[bool] = False
    ) -> ContextManager["InfraProvisioner"]:
        """
        :param skip_deployment: Set to True to skip stack creation and re-use existing stack without modifications.
            Also skips custom setup steps.
            Use-case: When you only want to regenerate the synthesized template without actually deploying.
        :param skip_teardown: Set to True to skip deleting any previously created stacks.
            Also skips custom teardown steps.
            Use-case: When you're dealing with resource-heavy stacks that take a long time to provision.
                The provisioner will perform a stack update instead of a create, should the stack still exist.

        Example usage:
        def my_fixture(infrastructure_setup):
            ...
            infra = infrastructure_setup(namespace="...")
            with infra.provisioner() as prov:
                yield prov
        """
        try:
            self.provision(skip_deployment=skip_deployment)
            # TODO: return "sub-view" on InfraProvisioner here for clearer API
            yield self
        finally:
            if not skip_teardown:
                self.teardown()
            else:
                LOG.debug("Skipping teardown. Resources and stacks are not deleted.")

    def provision(self, skip_deployment: Optional[bool] = False):
        """
        Execute all previously added custom provisioning steps and deploy added CDK stacks via CloudFormation.

        Already deployed stacks will be updated instead.
        """
        self._synth()
        if skip_deployment:
            LOG.debug("Skipping deployment. Assuming stacks have already been created")
            return

        is_update = False

        if all(
            self._is_stack_deployed(stack_name, stack)
            for stack_name, stack in self.cloudformation_stacks.items()
        ):
            LOG.debug("All stacks are already deployed. Skipping the provisioning.")
            # TODO: in localstack we might want to do a delete/create
            #  but generally this won't be a common use case when developing against LocalStack
            is_update = True

        self._bootstrap()
        self._run_manual_setup_tasks()
        for stack_name, stack in self.cloudformation_stacks.items():
            change_set_name = f"test-cs-{short_uid()}"
            if len(stack["Template"]) > CFN_MAX_TEMPLATE_SIZE:
                # if the template size is too big, we need to upload it to s3 first
                # and use TemplateURL instead to point to the template in s3
                template_bucket_name = self._template_bucket_name()
                self._create_bucket_if_not_exists(template_bucket_name)
                key = f"{stack_name}.yaml"
                self.aws_client.s3.put_object(
                    Bucket=template_bucket_name, Key=key, Body=stack["Template"]
                )
                url = self.aws_client.s3.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": template_bucket_name, "Key": key},
                    ExpiresIn=10,
                )

                change_set = self.aws_client.cloudformation.create_change_set(
                    StackName=stack_name,
                    ChangeSetName=change_set_name,
                    TemplateURL=url,
                    ChangeSetType="UPDATE" if is_update else "CREATE",
                    Capabilities=[
                        Capability.CAPABILITY_AUTO_EXPAND,
                        Capability.CAPABILITY_IAM,
                        Capability.CAPABILITY_NAMED_IAM,
                    ],
                )
            else:
                change_set = self.aws_client.cloudformation.create_change_set(
                    StackName=stack_name,
                    ChangeSetName=change_set_name,
                    TemplateBody=stack["Template"],
                    ChangeSetType="UPDATE" if is_update else "CREATE",
                    Capabilities=[
                        Capability.CAPABILITY_AUTO_EXPAND,
                        Capability.CAPABILITY_IAM,
                        Capability.CAPABILITY_NAMED_IAM,
                    ],
                )
            stack_id = self.cloudformation_stacks[stack_name]["StackId"] = change_set["StackId"]
            try:
                self.aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
                    ChangeSetName=change_set["Id"],
                    WaiterConfig=WAITER_CONFIG_AWS if is_aws_cloud() else WAITER_CONFIG_LS,
                )
            except WaiterError:
                # it's OK if we don't have any updates to perform here (!)
                # there is no specific error code unfortunately
                if not (is_update):
                    raise
                else:
                    LOG.warning("Execution of change set %s failed. Assuming no changes detected.")
            else:
                self.aws_client.cloudformation.execute_change_set(ChangeSetName=change_set["Id"])
                try:
                    self.aws_client.cloudformation.get_waiter(
                        "stack_update_complete" if is_update else "stack_create_complete"
                    ).wait(
                        StackName=stack_id,
                        WaiterConfig=WAITER_CONFIG_AWS if is_aws_cloud() else WAITER_CONFIG_LS,
                    )

                except WaiterError as e:
                    raise StackDeployError(
                        self.aws_client.cloudformation.describe_stacks(StackName=stack_id)[
                            "Stacks"
                        ][0],
                        self.aws_client.cloudformation.describe_stack_events(StackName=stack_id)[
                            "StackEvents"
                        ],
                    ) from e

            if stack["AutoCleanS3"]:
                stack_resources = self.aws_client.cloudformation.describe_stack_resources(
                    StackName=stack_id
                )["StackResources"]
                s3_buckets = [
                    r["PhysicalResourceId"]
                    for r in stack_resources
                    if r["ResourceType"] == "AWS::S3::Bucket"
                ]

                for s3_bucket in s3_buckets:
                    self.custom_cleanup_steps.append(
                        lambda bucket=s3_bucket: cleanup_s3_bucket(
                            self.aws_client.s3, bucket, delete_bucket=False
                        )
                    )

    # TODO: move this to a CFn testing utility
    def get_stack_outputs(self, stack_name: str) -> dict[str, str]:
        """
        A simple helper function to extract outputs of a deployed stack in a simple <key>:<value> format.
        """
        describe_stack = self.aws_client.cloudformation.describe_stacks(StackName=stack_name)
        raw_outputs = describe_stack["Stacks"][0].get("Outputs", {})
        outputs = {o["OutputKey"]: o["OutputValue"] for o in raw_outputs}
        return outputs

    def teardown(self):
        """
        Reverse operation of `InfraProvisioner.provision`.
        First performs any registered clean-up tasks in reverse order and afterwards deletes any previously created CloudFormation stacks
        """
        for fn in self.custom_cleanup_steps[::-1]:  # traverse in reverse order
            call_safe(fn)

        # TODO: dependency detection (coming with proper synth support)
        for stack_name, stack in reversed(self.cloudformation_stacks.items()):
            try:
                stack_id = stack.get("StackId", stack_name)
                self.aws_client.cloudformation.delete_stack(StackName=stack_id)
                self.aws_client.cloudformation.get_waiter("stack_delete_complete").wait(
                    StackName=stack_id,
                    WaiterConfig=WAITER_CONFIG_AWS if is_aws_cloud() else WAITER_CONFIG_LS,
                )
            except Exception:
                LOG.warning(
                    "Failed to delete stack %s",
                    stack_name,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
        # TODO log-groups created by lambda are not automatically cleaned up by CDK

        if not is_aws_cloud():
            # TODO: also clean up s3 bucket on localstack?
            #  does it even make sense to do a general "de-bootstrapping" after each test?
            try:
                self.aws_client.ssm.delete_parameter(Name=CDK_BOOTSTRAP_PARAM)
            except Exception:
                pass

        # clean & delete asset bucket
        cleanup_s3_bucket(self.aws_client.s3, self.get_asset_bucket(), delete_bucket=True)

    def add_cdk_stack(
        self,
        cdk_stack: cdk.Stack,
        autoclean_buckets: Optional[bool] = True,
    ):
        """
        Register a CDK stack to be deployed in a later `InfraProvisioner.provision` call.
        Custom tasks registered via `InfraProvisioner.add_custom_setup` will be executed before any stack deployments.

        CAVEAT: `InfraProvisioner` currently does not support CDK-generated assets.
                If you need any assets, such as zip files uploaded to s3, please use `InfraProvisioner.add_custom_setup`.
        """
        # TODO: unify this after refactoring existing usage
        if self.persist_output:
            dir_path = self._get_template_path()
            dir_path.mkdir(exist_ok=True, parents=True)
            template_path = dir_path / f"{cdk_stack.stack_name}.json"

            should_update_template = (
                is_env_true("TEST_CDK_FORCE_SYNTH") or self.force_synth
            )  # EXPERIMENTAL / API subject to change
            if not template_path.exists() or should_update_template:
                with open(template_path, "wt") as fd:
                    template_json = cdk.assertions.Template.from_stack(cdk_stack).to_json()
                    json.dump(template_json, fd, indent=2)
                    # add trailing newline for linter and Git compliance
                    fd.write("\n")

            self.cloudformation_stacks[cdk_stack.stack_name] = {
                "StackName": cdk_stack.stack_name,
                "Template": load_file(template_path),
                "AutoCleanS3": autoclean_buckets,
            }
        else:
            template_json = cdk.assertions.Template.from_stack(cdk_stack).to_json()
            template_str = json.dumps(template_json)
            self.cloudformation_stacks[cdk_stack.stack_name] = {
                "StackName": cdk_stack.stack_name,
                "Template": template_str,
                "AutoCleanS3": autoclean_buckets,
            }

    def add_custom_teardown(self, cleanup_task: Callable):
        """
        Register a custom teardown task.
        Anything registered here will be executed on InfraProvisioner.teardown BEFORE any stack deletions.
        """
        self.custom_cleanup_steps.append(cleanup_task)

    def add_custom_setup(self, setup_task: Callable):
        """
        Register a custom setup task.
        Anything registered here will be executed on InfraProvisioner.provision BEFORE any stack operations.
        """
        self.custom_setup_steps.append(setup_task)

    # TODO: remove after removing any usage
    def add_custom_setup_provisioning_step(self, setup_task: Callable):
        """
        DEPRECATED. Use add_custom_setup instead.

        Register a custom setup task.
        Anything registered here will be executed on InfraProvisioner.provision BEFORE any stack operations.
        """
        warnings.warn(
            "`add_custom_setup_provisioning_step` is deprecated. Use `add_custom_setup`",
            DeprecationWarning,
            stacklevel=2,
        )
        self.add_custom_setup(setup_task)

    def _bootstrap(self):
        # TODO: add proper bootstrap template to deploy here if there's no parameter yet
        self._create_bucket_if_not_exists(self.get_asset_bucket())

        try:
            self.aws_client.ssm.get_parameter(Name=CDK_BOOTSTRAP_PARAM)
        except self.aws_client.ssm.exceptions.ParameterNotFound:
            self.aws_client.ssm.put_parameter(Name=CDK_BOOTSTRAP_PARAM, Type="String", Value="10")

    def _run_manual_setup_tasks(self):
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
        return describe_stack["Stacks"][0]["StackStatus"] in [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_COMPLETE",
        ]

    def _get_template_path(self) -> Path:
        return Path(self.base_path) / self.namespace

    def _template_bucket_name(self):
        # TODO: unify this when we use the proper bootstrap template for wider asset support
        account_id = self.aws_client.sts.get_caller_identity()["Account"]
        region = self.aws_client.sts.meta.region_name
        return f"localstack-testing-assets-{account_id}-{region}"

    def _create_bucket_if_not_exists(self, template_bucket_name: str):
        try:
            self.aws_client.s3.head_bucket(Bucket=template_bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "404":
                raise
            create_s3_bucket(template_bucket_name, s3_client=self.aws_client.s3)

    def _synth(self):
        # TODO: this doesn't actually synth a CloudAssembly yet
        stacks = self.cdk_app.node.children
        if not stacks:
            return

        for stack in self.cdk_app.node.children:
            self.add_cdk_stack(cdk_stack=stack)

    # TODO: move to a util class/module
    @staticmethod
    def get_asset_bucket_cdk(stack: cdk.Stack):
        return cdk.Fn.join("-", ["localstack", "testing", stack.account, stack.region])
