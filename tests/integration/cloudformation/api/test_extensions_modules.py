import os

import pytest

from localstack.utils.strings import short_uid


class TestExtensionModule:
    @pytest.mark.skip(reason="feature not supported")
    def test_crud_module(self, deploy_cfn_template, cfn_client, s3_client, snapshot, cleanups):
        role_stack = "localstack-testing-testmodule-role-stack"

        execution_role_arn = deploy_cfn_template(
            stack_name=role_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/resource-role.yml"
            ),
            parameters={"ResourceType": "module/LocalStack-Testing-TestModule-MODULE"},
        ).outputs["ExecutionRoleArn"]

        infra_stack = "CloudFormationManagedUploadInfrastructure"
        stack = deploy_cfn_template(
            stack_name=infra_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/upload-infra.yml"
            ),
            max_wait=300,
        )

        bucket_name = stack.outputs["CloudFormationManagedUploadBucketName"]
        logs_role_arn = stack.outputs["LogAndMetricsDeliveryRoleArn"]

        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/modules/localstack-testing-testmodule-module.zip",
        )
        key_name = "localstack-testing-testmodule-module-2023-02-07T19-16-19.zip"
        s3_client.upload_file(artifact_path, bucket_name, key_name)
        register_response = cfn_client.register_type(
            Type="MODULE",
            TypeName="LocalStack::Testing::TestModule::MODULE",
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
            LoggingConfig={
                "LogRoleArn": logs_role_arn,
                "LogGroupName": "ls-testing-testmodule-logs",
            },
            ExecutionRoleArn=execution_role_arn,
            ClientRequestToken=f"token-{short_uid()}",
        )

        # TODO this should be in cleanups but they are not being executed before the stack deletion
        s3_client.delete_object(Bucket=bucket_name, Key=key_name)

        snapshot.add_transformer(
            snapshot.transform.key_value("RegistrationToken", "registration-token")
        )
        snapshot.add_transformer(snapshot.transform.key_value("LogRoleArn", "log-role-arn"))
        snapshot.add_transformer(snapshot.transform.key_value("LogGroupName", "log-group-name"))
        snapshot.add_transformer(
            snapshot.transform.key_value("ExecutionRoleArn", "execution-role-arn")
        )

        snapshot.match("register_response", register_response)

        describe_type_response = cfn_client.describe_type_registration(
            RegistrationToken=register_response["RegistrationToken"]
        )
        snapshot.match("describe_type_response", describe_type_response)

        describe_response = cfn_client.describe_type(
            Type="MODULE",
            Arn=describe_type_response["TypeArn"],
        )
        snapshot.match("describe_response", describe_response)

        list_response = cfn_client.list_type_registrations(
            Type="MODULE",
            TypeName="LocalStack::Testing::TestModule::MODULE",
        )
        snapshot.match("list_response", list_response)

        deregister_response = cfn_client.deregister_type(
            Arn=describe_type_response["TypeArn"], Type="MODULE"
        )
        snapshot.match("deregister_response", deregister_response)

    # @pytest.mark.skip(reason="feature not supported")
    def test_module_usage(self, deploy_cfn_template, cfn_client, s3_client, snapshot, cleanups):
        role_stack = "localstack-testing-testmodule-role-stack"

        execution_role_arn = deploy_cfn_template(
            stack_name=role_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/resource-role.yml"
            ),
            parameters={"ResourceType": "module/LocalStack-Testing-TestModule-MODULE"},
        ).outputs["ExecutionRoleArn"]

        infra_stack = "CloudFormationManagedUploadInfrastructure"
        stack = deploy_cfn_template(
            stack_name=infra_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/upload-infra.yml"
            ),
            max_wait=300,
        )

        bucket_name = stack.outputs["CloudFormationManagedUploadBucketName"]
        logs_role_arn = stack.outputs["LogAndMetricsDeliveryRoleArn"]

        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/modules/localstack-testing-testmodule-module.zip",
        )
        key_name = "localstack-testing-testmodule-module-2023-02-07T19-16-19.zip"
        s3_client.upload_file(artifact_path, bucket_name, key_name)
        register_response = cfn_client.register_type(
            Type="MODULE",
            TypeName="LocalStack::Testing::TestModule::MODULE",
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
            LoggingConfig={
                "LogRoleArn": logs_role_arn,
                "LogGroupName": "ls-testing-testmodule-logs",
            },
            ExecutionRoleArn=execution_role_arn,
            ClientRequestToken=f"token-{short_uid()}",
        )

        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=register_response["RegistrationToken"]
        )

        # TODO this should be in cleanups but they are not being executed before the stack deletion
        s3_client.delete_object(Bucket=bucket_name, Key=key_name)

        template_path = os.path.join(
            os.path.dirname(__file__),
            "../../templates/registry/module.yml",
        )

        stack = deploy_cfn_template(
            template_path=template_path, parameters={"Name": f"name-{short_uid()}"}, max_wait=300
        )
        resources = cfn_client.describe_stack_resources(StackName=stack.stack_name)[
            "StackResources"
        ]

        snapshot.match("outputs", stack.outputs)
        snapshot.match("resource_description", resources[0])

        cleanups.append(lambda: s3_client.delete_object(Bucket=bucket_name, Key=key_name))
        cleanups.append(
            lambda: cfn_client.deregister_type(
                TypeName="LocalStack::Testing::TestModule::MODULE", Type="MODULE"
            )
        )
