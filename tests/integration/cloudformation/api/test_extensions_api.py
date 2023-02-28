import os
import re

import botocore
import botocore.exceptions
import pytest

from localstack.utils.strings import short_uid


class TestExtensionsApi:
    @pytest.mark.skip(reason="feature not implemented")
    @pytest.mark.parametrize(
        "extension_type, extension_name, artifact",
        [
            (
                "RESOURCE",
                "LocalStack::Testing::TestResource",
                "resourcetypes/localstack-testing-testresource.zip",
            ),
            (
                "MODULE",
                "LocalStack::Testing::TestModule::MODULE",
                "modules/localstack-testing-testmodule-module.zip",
            ),
            ("HOOK", "LocalStack::Testing::TestHook", "hooks/localstack-testing-testhook.zip"),
        ],
    )
    def test_crud_extension(
        self,
        deploy_cfn_template,
        s3_bucket,
        cfn_client,
        s3_client,
        snapshot,
        extension_name,
        extension_type,
        artifact,
    ):
        bucket_name = s3_bucket
        artifact_path = os.path.join(
            os.path.dirname(__file__), "../artifacts/extensions/", artifact
        )
        key_name = f"key-{short_uid()}"
        s3_client.upload_file(artifact_path, bucket_name, key_name)

        register_response = cfn_client.register_type(
            Type=extension_type,
            TypeName=extension_name,
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
        )

        snapshot.add_transformer(
            snapshot.transform.key_value("RegistrationToken", "registration-token")
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("DefaultVersionId", "default-version-id")
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

        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=register_response["RegistrationToken"]
        )

        describe_response = cfn_client.describe_type(
            Arn=describe_type_response["TypeArn"],
        )
        snapshot.match("describe_response", describe_response)

        list_response = cfn_client.list_type_registrations(
            TypeName=extension_name,
        )
        snapshot.match("list_response", list_response)

        deregister_response = cfn_client.deregister_type(Arn=describe_type_response["TypeArn"])
        snapshot.match("deregister_response", deregister_response)

    @pytest.mark.skip(reason="test not completed")
    def test_extension_versioning(self, s3_client, s3_bucket, cfn_client, snapshot):
        bucket_name = s3_bucket
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/modules/localstack-testing-testmodule-module.zip",
        )
        key_name = f"key-{short_uid()}"
        s3_client.upload_file(artifact_path, bucket_name, key_name)

        register_response = cfn_client.register_type(
            Type="MODULE",
            TypeName="LocalStack::Testing::TestModule::MODULE",
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
        )
        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=register_response["RegistrationToken"]
        )

        register_response = cfn_client.register_type(
            Type="MODULE",
            TypeName="LocalStack::Testing::TestModule::MODULE",
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
        )
        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=register_response["RegistrationToken"]
        )

        versions_response = cfn_client.list_type_versions(
            TypeName="LocalStack::Testing::TestModule::MODULE", Type="MODULE"
        )
        snapshot.match("versions", versions_response)

        set_default_response = cfn_client.set_type_default_version(
            Arn=versions_response["TypeVersionSummaries"][1]["Arn"]
        )
        snapshot.match("set_default_response", set_default_response)

        with pytest.raises(botocore.errorfactory.CFNRegistryException) as e:
            cfn_client.deregister_type(
                Type="MODULE", TypeName="LocalStack::Testing::TestModule::MODULE"
            )
        snapshot.match("multiple_versions_error", e.value.response)

        arn = versions_response["TypeVersionSummaries"][1]["Arn"]
        with pytest.raises(botocore.exceptions.TypeNotFound) as e:
            arn = re.sub(r"/\d{8}", "99999999", arn)
            cfn_client.deregister_type(Arn=arn)
        snapshot.match("version_not_found_error", e.value.response)

        delete_first_version_response = cfn_client.deregister_type(
            Arn=versions_response["TypeVersionSummaries"][0]["Arn"]
        )
        snapshot.match("delete_unused_version_response", delete_first_version_response)

        with pytest.raises(botocore.errorfactory.CFNRegistryException) as e:
            cfn_client.deregister_type(Arn=versions_response["TypeVersionSummaries"][0]["Arn"])
        snapshot.match("error_for_deleting_default_with_arn", e.value.response)

        delete_default_response = cfn_client.deregister_type(
            Type="MODULE", TypeName="LocalStack::Testing::TestModule::MODULE"
        )
        snapshot.match("deleting_default_response", delete_default_response)

    @pytest.mark.skip(reason="feature not implemented")
    def test_extension_not_complete(self, s3_client, s3_bucket, cfn_client, snapshot):
        bucket_name = s3_bucket
        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "../artifacts/extensions/hooks/localstack-testing-testhook.zip",
        )
        key_name = f"key-{short_uid()}"
        s3_client.upload_file(artifact_path, bucket_name, key_name)

        register_response = cfn_client.register_type(
            Type="HOOK",
            TypeName="LocalStack::Testing::TestHook",
            SchemaHandlerPackage=f"s3://{bucket_name}/{key_name}",
        )

        with pytest.raises(Exception) as e:
            cfn_client.describe_type(Type="HOOK", TypeName="LocalStack::Testing::TestHook")
        snapshot.match("not_found_error", e.value)

        cfn_client.get_waiter("type_registration_complete").wait(
            RegistrationToken=register_response["RegistrationToken"]
        )
        cfn_client.deregister_type(
            Type="HOOK",
            TypeName="LocalStack::Testing::TestHook",
        )
