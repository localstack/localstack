import os

from localstack.utils.strings import short_uid


class TestExtensionResourceTypes:
    def test_crud_resource_type(self, deploy_cfn_template, cfn_client, s3_client, snapshot):
        role_stack = "ls-testing-test-role-stack"

        execution_role_arn = deploy_cfn_template(
            stack_name=role_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/resource-role.yml"
            ),
        ).outputs["ExecutionRoleArn"]

        infra_stack = "CloudFormationManagedUploadInfrastructure"
        stack = deploy_cfn_template(
            stack_name=infra_stack,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/registry/upload-infra.yml"
            ),
        )

        bucket_name = stack.outputs["CloudFormationManagedUploadBucketName"]
        logs_role_arn = stack.outputs["LogAndMetricsDeliveryRoleArn"]

        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/resourcetypes/localstack-testing-testresource.zip",
        )
        key_name = "ls-testing-test-2023-02-07T19-16-19.zip"
        s3_client.upload_file(artifact_path, bucket_name, key_name)
        register_response = cfn_client.register_type(
            Type="RESOURCE",
            TypeName="LS::Testing::Test",
            SchemaHandlerPackage=f"{bucket_name}/{key_name}",
            LoggingConfig={"LogRoleArn": logs_role_arn, "LogGroupName": "ls-testing-test-logs"},
            ExecutionRoleArn=execution_role_arn,
            ClientRequestToken=f"token-{short_uid()}",
        )
        snapshot.match("register_response", register_response)

        describe_response = cfn_client.describe_type_registration(
            RegistrationToken=register_response["RegistrationToken"]
        )
        snapshot.match("describe_response", describe_response)

        list_response = cfn_client.list_type_registrations(
            TypeName="LS::Testing::Test",
        )
        snapshot.match("list_response", list_response)

        deregister_response = cfn_client.deregister_type(
            TypeName="LS::Testing::Test", VersionId=describe_response["LatestPublicVersion"]
        )
        snapshot.match("deregister_response", deregister_response)
