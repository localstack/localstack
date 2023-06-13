import os.path

import pytest

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_DIR = os.path.dirname(__file__)


class TestCloudFormationConditions:
    """
    TODO: what happens to outputs that reference a resource that isn't deployed?
    """

    @pytest.mark.skip(reason="because I say so")
    def test_evaluation_order(self, aws_client):
        """
        Explore evaluation order of conditions

        1. Parameters
        2. Macros/Transformations
        3. Conditions
        4. Intrinsic functions
        """
        ...

    @pytest.mark.aws_validated
    def test_simple_condition_evaluation_deploys_resource(
        self, aws_client, deploy_cfn_template, cleanups
    ):
        topic_name = f"test-topic-{short_uid()}"
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../templates/conditions/simple-condition.yaml"
            ),
            parameters={"OptionParameter": "option-a", "TopicName": topic_name},
        )
        # verify that CloudFormation includes the resource
        stack_resources = aws_client.cloudformation.describe_stack_resources(
            StackName=deployment.stack_id
        )
        assert stack_resources["StackResources"]

        # verify actual resource deployment
        assert [
            t
            for t in aws_client.sns.get_paginator("list_topics")
            .paginate()
            .build_full_result()["Topics"]
            if topic_name in t["TopicArn"]
        ]

    @pytest.mark.aws_validated
    def test_simple_condition_evaluation_doesnt_deploy_resource(
        self, aws_client, deploy_cfn_template, cleanups
    ):
        """Note: Conditions allow us to deploy stacks that won't actually contain any deployed resources"""
        topic_name = f"test-topic-{short_uid()}"
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../templates/conditions/simple-condition.yaml"
            ),
            parameters={"OptionParameter": "option-b", "TopicName": topic_name},
        )
        # verify that CloudFormation ignores the resource
        aws_client.cloudformation.describe_stack_resources(StackName=deployment.stack_id)
        # assert stack_resources['StackResources'] == []

        # verify actual resource deployment
        assert [
            t for t in aws_client.sns.list_topics()["Topics"] if topic_name in t["TopicArn"]
        ] == []

    @pytest.mark.parametrize(
        "should_set_custom_name",
        [
            # "yep",
            "nope"
        ],
    )
    @pytest.mark.aws_validated
    def test_simple_intrinsic_fn_condition_evaluation(
        self, aws_client, deploy_cfn_template, should_set_custom_name
    ):
        """
        Tests a simple Fn::If condition evaluation

        The conditional ShouldSetCustomName (yep | nope) switches between an autogenerated and a predefined name for the topic

        TODO: this also works with the simple-intrinsic-condition-name-conflict.yaml template where the ID of the condition and the ID of the parameter are the same(!).
            It is currently broken in LocalStack
        """
        topic_name = f"test-topic-{short_uid()}"
        deployment = deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../templates/conditions/simple-intrinsic-condition.yaml"
            ),
            parameters={
                "TopicName": topic_name,
                "ShouldSetCustomName": should_set_custom_name,
            },
        )
        # verify that the topic has the correct name
        topic_arn = deployment.outputs["TopicArn"]
        if should_set_custom_name == "yep":
            assert topic_name in topic_arn
        else:
            assert topic_name not in topic_arn

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="because I say so")
    def test_dependent_ref(self, aws_client, snapshot):
        """
        Tests behavior of a stack with 2 resources where one depends on the other.
        The referenced resource won't be deployed due to its condition evaluating to false, so the ref can't be resolved.

        This immediately leads to an error.
        """
        topic_name = f"test-topic-{short_uid()}"
        ssm_param_name = f"test-param-{short_uid()}"

        stack_name = f"test-condition-ref-stack-{short_uid()}"
        changeset_name = "initial"
        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName=changeset_name,
                ChangeSetType="CREATE",
                TemplateBody=load_file(
                    os.path.join(THIS_DIR, "../../templates/conditions/ref-condition.yaml")
                ),
                Parameters=[
                    {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                    {"ParameterKey": "SsmParamName", "ParameterValue": ssm_param_name},
                    {"ParameterKey": "OptionParameter", "ParameterValue": "option-b"},
                ],
            )
        snapshot.match("dependent_ref_exc", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="because I say so")
    def test_dependent_ref_intrinsic_fn_condition(self, aws_client, deploy_cfn_template):
        """
        Checks behavior of un-refable
        """
        topic_name = f"test-topic-{short_uid()}"
        ssm_param_name = f"test-param-{short_uid()}"

        deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../templates/conditions/ref-condition-intrinsic-condition.yaml"
            ),
            parameters={
                "TopicName": topic_name,
                "SsmParamName": ssm_param_name,
                "OptionParameter": "option-b",
            },
        )

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="because I say so")
    def test_dependent_ref_with_macro(
        self, aws_client, deploy_cfn_template, lambda_su_role, cleanups
    ):
        """

        specifying option-b would normally lead to an error without the macro because of the unresolved ref.
        Because the macro replaced the resources though, the test passes. We've shown that conditions aren't fully evaluated before the transformations

        A few interesting findings:
        * macros are not allowed to transform Parameters (macro invocation by CFn will fail in this case)

        """

        log_group_name = f"test-log-group-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)

        deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../templates/conditions/ref-condition-macro-def.yaml"
            ),
            parameters={
                "FnRole": lambda_su_role,
                "LogGroupName": log_group_name,
                "LogRoleARN": lambda_su_role,
            },
        )

        topic_name = f"test-topic-{short_uid()}"
        ssm_param_name = f"test-param-{short_uid()}"
        stack_name = f"test-condition-ref-macro-stack-{short_uid()}"
        changeset_name = "initial"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=changeset_name,
            ChangeSetType="CREATE",
            TemplateBody=load_file(
                os.path.join(THIS_DIR, "../../templates/conditions/ref-condition-macro.yaml")
            ),
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                {"ParameterKey": "SsmParamName", "ParameterValue": ssm_param_name},
                {"ParameterKey": "OptionParameter", "ParameterValue": "option-b"},
            ],
        )

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=changeset_name, StackName=stack_name
        )

        # # verify that CloudFormation ignores the resource
        # stack_resources = aws_client.cloudformation.describe_stack_resources(StackName=deployment.stack_id)
        # # assert stack_resources['StackResources'] == []
        #
        # # verify actual resource deployment
        # assert [t for t in aws_client.sns.list_topics()['Topics'] if topic_name in t['TopicArn']]
        # # assert [t for t in aws_client.sns.list_topics()['Topics'] if topic_name in t['TopicArn']] == []
        # param = aws_client.ssm.get_parameter(Name=ssm_param_name)
        # assert param['Parameter']['Value']

    # TODO: implement
    @pytest.mark.parametrize(
        ["env_type", "should_create_bucket", "should_create_policy"],
        [
            ("test", False, False),
            ("test", True, False),
            ("prod", False, False),
            ("prod", True, True),
        ],
        ids=[
            "test-nobucket-nopolicy",
            "test-bucket-nopolicy",
            "prod-nobucket-nopolicy",
            "prod-bucket-policy",
        ],
    )
    @pytest.mark.skip(reason="because I say so")
    def test_nested_conditions(
        self,
        aws_client,
        deploy_cfn_template,
        cleanups,
        env_type,
        should_create_bucket,
        should_create_policy,
        snapshot,
    ):
        """
        EnvType == "prod" && BucketName != "" ==> creates bucket + policy
        EnvType == "test" && BucketName != "" ==> creates bucket only
        EnvType == "test" && BucketName == "" ==> no resource created
        EnvType == "prod" && BucketName == "" ==> no resource created
        """
        bucket_name = f"ls-test-bucket-{short_uid()}" if should_create_bucket else ""
        stack_name = f"condition-test-stack-{short_uid()}"
        changeset_name = "initial"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        if bucket_name:
            snapshot.add_transformer(snapshot.transform.regex(bucket_name, "<bucket-name>"))
        snapshot.add_transformer(snapshot.transform.regex(stack_name, "<stack-name>"))

        template = load_file(
            os.path.join(THIS_DIR, "../../templates/conditions/nested-conditions.yaml")
        )
        create_cs_result = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=changeset_name,
            TemplateBody=template,
            ChangeSetType="CREATE",
            Parameters=[
                {"ParameterKey": "EnvType", "ParameterValue": env_type},
                {"ParameterKey": "BucketName", "ParameterValue": bucket_name},
            ],
        )
        snapshot.match("create_cs_result", create_cs_result)

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=changeset_name, StackName=stack_name
        )

        describe_changeset_result = aws_client.cloudformation.describe_change_set(
            ChangeSetName=changeset_name, StackName=stack_name
        )
        snapshot.match("describe_changeset_result", describe_changeset_result)
        aws_client.cloudformation.execute_change_set(
            ChangeSetName=changeset_name, StackName=stack_name
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

        stack_resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_name)
        if should_create_policy:
            stack_policy = [
                sr
                for sr in stack_resources["StackResources"]
                if sr["ResourceType"] == "AWS::S3::BucketPolicy"
            ][0]
            snapshot.add_transformer(
                snapshot.transform.regex(stack_policy["PhysicalResourceId"], "<stack-policy>"),
                priority=-1,
            )

        snapshot.match("stack_resources", stack_resources)
        stack_events = aws_client.cloudformation.describe_stack_events(StackName=stack_name)
        snapshot.match("stack_events", stack_events)
        describe_stack_result = aws_client.cloudformation.describe_stacks(StackName=stack_name)
        snapshot.match("describe_stack_result", describe_stack_result)

        # manual assertions

        # check that bucket exists
        try:
            aws_client.s3.head_bucket(Bucket=bucket_name)
            bucket_exists = True
        except Exception:
            bucket_exists = False

        assert bucket_exists == should_create_bucket

        if bucket_exists:
            # check if a policy exists on the bucket
            try:
                aws_client.s3.get_bucket_policy(Bucket=bucket_name)
                bucket_policy_exists = True
            except Exception:
                bucket_policy_exists = False

            assert bucket_policy_exists == should_create_policy

    # def test_updating_only_conditions_during_stack_update(self):
    #     ...

    # def test_condition_with_unsupported_intrinsic_functions(self):
    # ...
