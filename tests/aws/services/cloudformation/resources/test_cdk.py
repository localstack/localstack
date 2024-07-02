import os

import pytest
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


class TestCdkInit:
    @pytest.mark.parametrize("bootstrap_version", ["10", "11", "12"])
    @markers.aws.validated
    def test_cdk_bootstrap(self, deploy_cfn_template, bootstrap_version, aws_client):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                f"../../../templates/cdk_bootstrap_v{bootstrap_version}.yaml",
            ),
            parameters={"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"},
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
    def test_cdk_bootstrap_redeploy(self, aws_client, cleanup_stacks, cleanup_changesets, cleanups):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""

        stack_name = f"CDKToolkit-{short_uid()}"
        change_set_name = f"cdk-deploy-change-set-{short_uid()}"

        def clean_resources():
            cleanup_stacks([stack_name])
            cleanup_changesets([change_set_name])

        cleanups.append(clean_resources)

        template_body = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/cdk_bootstrap.yml")
        )
        aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_body,
            ChangeSetType="CREATE",
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            Description="CDK Changeset for execution 731ed7da-8b2d-49c6-bca3-4698b6875954",
            Parameters=[
                {
                    "ParameterKey": "BootstrapVariant",
                    "ParameterValue": "AWS CDK: Default Resources",
                },
                {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
                {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
                {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
                {"ParameterKey": "FileAssetsBucketKmsKeyId", "ParameterValue": "AWS_MANAGED_KEY"},
                {"ParameterKey": "PublicAccessBlockConfiguration", "ParameterValue": "true"},
                {"ParameterKey": "Qualifier", "ParameterValue": "hnb659fds"},
                {"ParameterKey": "UseExamplePermissionsBoundary", "ParameterValue": "false"},
            ],
        )
        aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            StackName=stack_name, ChangeSetName=change_set_name
        )

        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )

        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)
        aws_client.cloudformation.describe_stacks(StackName=stack_name)

        # When CDK toolstrap command is executed again it just confirms that the template is the same
        aws_client.sts.get_caller_identity()
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
