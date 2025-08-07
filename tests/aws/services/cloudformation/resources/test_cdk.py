import os

import pytest
from botocore.exceptions import WaiterError
from localstack_snapshot.snapshots.transformer import SortingTransformer
from tests.aws.services.cloudformation.conftest import skip_if_v1_provider, skip_if_v2_provider

from localstack.aws.api.cloudformation import ChangeSetType
from localstack.testing.pytest import markers
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Outputs",
        ]
    )
    @skip_if_v2_provider(
        reason="CFNV2:Engine changes are detected during redeploy when they shouldn't be"
    )
    @skip_if_v1_provider(reason="Changes are detected during redeploy when they shouldn't be")
    def test_cdk_bootstrap_redeploy_2(self, aws_client, deploy_cfn_template, snapshot):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""
        snapshot.add_transformers_list(snapshot.transform.cloudformation_api() + [])
        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../../templates/cdk_bootstrap_v28.yaml",
        )
        # we have to specify a qualifier to make sure we don't get output collisions
        qualifier = short_uid()
        snapshot.add_transformer(snapshot.transform.regex(qualifier, "<qualifier>"))
        snapshot.add_transformer(SortingTransformer("Parameters", lambda p: p["ParameterKey"]))

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
            template_path=template_path,
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

        # on AWS the stack does not redeploy as we have not changed anything
        change_set_name = f"cs-{short_uid()}"
        with open(template_path) as infile:
            template_body = infile.read()

        aws_client.cloudformation.create_change_set(
            StackName=stack.stack_id,
            ChangeSetName=change_set_name,
            TemplateBody=template_body,
            Parameters=parameters_2,
            ChangeSetType=ChangeSetType.UPDATE,
        )
        with pytest.raises(WaiterError):
            aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
                ChangeSetName=change_set_name, StackName=stack.stack_id
            )
        describe_cs = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_name, StackName=stack.stack_id
        )
        snapshot.match("failed-change-set", describe_cs)


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
