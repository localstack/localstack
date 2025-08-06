import os

import pytest
from localstack_snapshot.snapshots.transformer import SortingTransformer
from tests.aws.services.cloudformation.conftest import skip_if_v2_provider

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
    def test_cdk_bootstrap_redeploy(self, aws_client, deploy_cfn_template, snapshot):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""
        snapshot.add_transformers_list(snapshot.transform.cloudformation_api() + [])

        # we have to specify a qualifier to make sure we don't get output collisions
        qualifier = short_uid()

        # deploy 1
        parameters = {
            "CloudFormationExecutionPolicies": "",
            "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
            "PublicAccessBlockConfiguration": "true",
            "TrustedAccounts": "",
            "TrustedAccountsForLookup": "",
            # additional parameters not supplied by CDK
            "Qualifier": qualifier,
        }
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "../../../templates/cdk_bootstrap_v28.yaml",
            ),
            parameters=parameters,
        )
        stack_describe = aws_client.cloudformation.describe_stacks(StackName=stack.stack_id)[
            "Stacks"
        ][0]
        snapshot.match("describe-1", stack_describe)

        parameters_2 = [
            {"ParameterKey": "CloudFormationExecutionPolicies", "ParameterValue": ""},
            {"ParameterKey": "FileAssetsBucketKmsKeyId", "UsePreviousValue": True},
            {"ParameterKey": "PublicAccessBlockConfiguration", "ParameterValue": "true"},
            {"ParameterKey": "TrustedAccounts", "ParameterValue": ""},
            {"ParameterKey": "TrustedAccountsForLookup", "ParameterValue": ""},
            # additional parameters not supplied by CDK
            {"ParameterKey": "Qualifier", "UsePreviousValue": True},
        ]

        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "../../../templates/cdk_bootstrap_v28.yaml",
            ),
            raw_parameters=parameters_2,
            is_update=True,
            stack_name=stack.stack_id,
        )
        stack_describe = aws_client.cloudformation.describe_stacks(StackName=stack.stack_id)[
            "Stacks"
        ][0]
        snapshot.match("describe-2", stack_describe)


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
