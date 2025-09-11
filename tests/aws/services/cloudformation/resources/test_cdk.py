import os
from collections.abc import Callable

import pytest
from localstack_snapshot.snapshots.transformer import SortingTransformer
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.aws.api.cloudformation import Parameter
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


class TestCdkInit:
    @pytest.mark.parametrize(
        "bootstrap_version,parameters",
        [
            ("10", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            ("11", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            ("12", {"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"}),
            (
                "28",
                {
                    "CloudFormationExecutionPolicies": "",
                    "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
                    "PublicAccessBlockConfiguration": "true",
                    "TrustedAccounts": "",
                    "TrustedAccountsForLookup": "",
                },
            ),
        ],
        ids=["10", "11", "12", "28"],
    )
    @markers.aws.validated
    def test_cdk_bootstrap(self, deploy_cfn_template, aws_client, bootstrap_version, parameters):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                f"../../../templates/cdk_bootstrap_v{bootstrap_version}.yaml",
            ),
            parameters=parameters,
        )
        init_stack_result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cdk_init_template.yaml"
            )
        )
        assert init_stack_result.outputs["BootstrapVersionOutput"] == bootstrap_version
        stack_res = aws_client.cloudformation.describe_stack_resources(
            StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
        )
        assert len(stack_res["StackResources"]) == 1
        assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template,parameters_fn",
        [
            pytest.param(
                "cdk_bootstrap.yml",
                lambda qualifier: [
                    {
                        "ParameterKey": "BootstrapVariant",
                        "ParameterValue": "AWS CDK: Default Resources",
                    },
                    {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
                    {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
                    {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
                    {
                        "ParameterKey": "FileAssetsBucketKmsKeyId",
                        "ParameterValue": "AWS_MANAGED_KEY",
                    },
                    {
                        "ParameterKey": "PublicAccessBlockConfiguration",
                        "ParameterValue": "true",
                    },
                    {"ParameterKey": "Qualifier", "ParameterValue": qualifier},
                    {
                        "ParameterKey": "UseExamplePermissionsBoundary",
                        "ParameterValue": "false",
                    },
                ],
                id="v20",
            ),
            pytest.param(
                "cdk_bootstrap_v28.yaml",
                lambda qualifier: [
                    {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
                    {
                        "ParameterKey": "FileAssetsBucketKmsKeyId",
                        "ParameterValue": "AWS_MANAGED_KEY",
                    },
                    {
                        "ParameterKey": "PublicAccessBlockConfiguration",
                        "ParameterValue": "true",
                    },
                    {"ParameterKey": "Qualifier", "ParameterValue": qualifier},
                    {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
                    {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
                ],
                id="v28",
            ),
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Wrong format, they are our internal parameter format
            "$..Parameters",
            # from the list of changes
            "$..Changes..Details",
            "$..Changes..LogicalResourceId",
            "$..Changes..ResourceType",
            "$..Changes..Scope",
            # provider
            "$..IncludeNestedStacks",
            # mismatch between amazonaws.com and localhost.localstack.cloud
            "$..Outputs..OutputValue",
            "$..Outputs..Description",
        ]
    )
    @skip_if_legacy_engine()
    def test_cdk_bootstrap_redeploy(
        self,
        aws_client,
        cleanup_stacks,
        cleanup_changesets,
        cleanups,
        snapshot,
        template,
        parameters_fn: Callable[[str], list[Parameter]],
    ):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(SortingTransformer("Parameters", lambda p: p["ParameterKey"]))
        snapshot.add_transformer(SortingTransformer("Outputs", lambda p: p["OutputKey"]))

        stack_name = f"CDKToolkit-{short_uid()}"
        change_set_name = f"cdk-deploy-change-set-{short_uid()}"
        qualifier = short_uid()
        snapshot.add_transformer(snapshot.transform.regex(qualifier, "<qualifier>"))

        def clean_resources():
            cleanup_stacks([stack_name])
            cleanup_changesets([change_set_name])

        cleanups.append(clean_resources)

        template_path = os.path.realpath(
            os.path.join(os.path.dirname(__file__), f"../../../templates/{template}")
        )
        template_body = load_file(template_path)
        if template_body is None:
            raise RuntimeError(f"Template {template_path} not loaded")

        aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_body,
            ChangeSetType="CREATE",
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            Description="CDK Changeset for execution 731ed7da-8b2d-49c6-bca3-4698b6875954",
            Parameters=parameters_fn(qualifier),
        )
        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            StackName=stack_name, ChangeSetName=change_set_name
        )
        describe_change_set = aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )
        snapshot.match("describe-change-set", describe_change_set)

        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )

        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)
        stacks = aws_client.cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
        snapshot.match("describe-stacks", stacks)

        # When CDK bootstrap command is executed again it just confirms that the template is the same
        aws_client.cloudformation.get_template(StackName=stack_name, TemplateStage="Original")

        # TODO: create scenario where the template is different to catch cdk behavior


class TestCdkSampleApp:
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Attributes.Policy.Statement..Condition",
            "$..Attributes.Policy.Statement..Resource",
            "$..StackResourceSummaries..PhysicalResourceId",
        ]
    )
    @markers.aws.validated
    def test_cdk_sample(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(
            SortingTransformer("StackResourceSummaries", lambda x: x["LogicalResourceId"]),
            priority=-1,
        )

        deploy = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cfn_cdk_sample_app.yaml"
            ),
            max_wait=120,
        )

        queue_url = deploy.outputs["QueueUrl"]

        queue_attr_policy = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"]
        )
        snapshot.match("queue_attr_policy", queue_attr_policy)
        stack_resources = aws_client.cloudformation.list_stack_resources(StackName=deploy.stack_id)
        snapshot.match("stack_resources", stack_resources)

        # physical resource id of the queue policy AWS::SQS::QueuePolicy
        queue_policy_resource = aws_client.cloudformation.describe_stack_resource(
            StackName=deploy.stack_id, LogicalResourceId="CdksampleQueuePolicyFA91005A"
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                queue_policy_resource["StackResourceDetail"]["PhysicalResourceId"],
                "<queue-policy-physid>",
            )
        )
        # TODO: make sure phys id of the resource conforms to this format: stack-d98dcad5-CdksampleQueuePolicyFA91005A-1WYVV4PMCWOYI
