"""
API-focused tests only. Don't add tests for asynchronous, blocking or implicit behavior here.

# TODO: create a re-usable pattern for fairly reproducible scenarios with slower updates/creates to test intermediary states
# TODO: code signing https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
# TODO: file systems https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html
# TODO: VPC config https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html

"""
import json
from io import BytesIO

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    is_old_provider,
    update_done,
)
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from localstack.utils.testutil import create_lambda_archive
from tests.integration.awslambda.test_lambda import (
    FUNCTION_MAX_UNZIPPED_SIZE,
    TEST_LAMBDA_INTROSPECT_PYTHON,
    TEST_LAMBDA_NODEJS,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_VERSION,
)


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(
        snapshot.transform.key_value("CodeSha256", reference_replacement=False)
    )


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaFunction:

    # TODO: maybe need to wait for each update to be active?
    @pytest.mark.aws_validated
    def test_function_lifecycle(
        self, lambda_client, snapshot, create_lambda_function, lambda_su_role
    ):
        """Tests CRUD for the lifecycle of a Lambda function and its config"""
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
            MemorySize=256,
            Timeout=5,
        )
        snapshot.match("create_response", create_response)

        get_function_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_response", get_function_response)

        update_func_conf_response = lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime=Runtime.python3_8,
            Description="Changed-Description",
            MemorySize=512,
            Timeout=10,
            Environment={"Variables": {"ENV_A": "a"}},
        )
        snapshot.match("update_func_conf_response", update_func_conf_response)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postupdate = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_postupdate", get_function_response_postupdate)

        zip_f = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True)
        update_code_response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_f,
        )
        snapshot.match("update_code_response", update_code_response)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postcodeupdate = lambda_client.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_function_response_postcodeupdate", get_function_response_postcodeupdate)

        delete_response = lambda_client.delete_function(FunctionName=function_name)
        snapshot.match("delete_response", delete_response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function(FunctionName=function_name)
        snapshot.match("delete_postdelete", e.value.response)

    @pytest.mark.aws_validated
    def test_redundant_updates(self, lambda_client, create_lambda_function, snapshot):
        """validates that redundant updates work (basically testing idempotency)"""
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        snapshot.match("create_response", create_response)

        first_update_result = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("first_update_result", first_update_result)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_fn_config_result = lambda_client.get_function_configuration(FunctionName=function_name)
        snapshot.match("get_fn_config_result", get_fn_config_result)

        get_fn_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        redundant_update_result = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("redundant_update_result", redundant_update_result)

    @pytest.mark.parametrize(
        "clientfn",
        [
            "delete_function",
            "get_function",
            "get_function_configuration",
            "get_function_url_config",
            "get_function_code_signing_config",
            "get_function_event_invoke_config",
            "get_function_concurrency",
        ],
    )
    @pytest.mark.aws_validated
    def test_ops_on_nonexisting_fn(self, lambda_client, snapshot, clientfn):
        """Test API responses on non-existing function names"""
        # technically the short_uid isn't really required but better safe than sorry
        function_name = f"i-dont-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<nonexisting-fn-name>"))
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            method = getattr(lambda_client, clientfn)
            method(FunctionName=function_name)
        snapshot.match("not_found_exception", e.value.response)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaVersions:
    @pytest.mark.aws_validated
    def test_publish_version_on_create(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Publish=True,
        )
        snapshot.match("create_response", create_response)

        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        list_versions_result = lambda_client.list_versions_by_function(FunctionName=function_name)
        snapshot.match("list_versions_result", list_versions_result)

    @pytest.mark.aws_validated
    def test_version_lifecycle(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        """
        Test the function version "lifecycle" (there are no deletes)
        """
        waiter = lambda_client.get_waiter("function_updated_v2")
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)

        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        list_versions_result = lambda_client.list_versions_by_function(FunctionName=function_name)
        snapshot.match("list_versions_result", list_versions_result)

        first_update_response = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="First version :)"
        )
        snapshot.match("first_update_response", first_update_response)
        waiter.wait(FunctionName=function_name)

        first_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)

        second_update_response = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="Second version :))"
        )
        snapshot.match("second_update_response", second_update_response)
        waiter.wait(FunctionName=function_name)

        # Same state published as two different versions.
        # The publish_version api is idempotent, so the second publish_version will *NOT* create a new version because $LATEST hasn't been updated!
        second_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Second version description :))"
        )
        snapshot.match("second_publish_response", second_publish_response)
        third_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Third version description :)))"
        )
        snapshot.match("third_publish_response", third_publish_response)

        list_versions_result_end = lambda_client.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result_end", list_versions_result_end)

    @pytest.mark.aws_validated
    def test_publish_with_wrong_revisionid(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create_response", create_response)

        get_fn_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # state change causes rev id change!
        assert create_response["RevisionId"] != get_fn_response["Configuration"]["RevisionId"]

        # publish_versions fails for the wrong revision id
        with pytest.raises(lambda_client.exceptions.PreconditionFailedException) as e:
            lambda_client.publish_version(FunctionName=function_name, RevisionId="doesntexist")
        snapshot.match("publish_wrong_revisionid_exc", e.value.response)

        # but with the proper rev id, it should work
        publish_result = lambda_client.publish_version(
            FunctionName=function_name, RevisionId=get_fn_response["Configuration"]["RevisionId"]
        )
        snapshot.match("publish_result", publish_result)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaAlias:
    @pytest.mark.aws_validated
    def test_alias_lifecycle(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        """
        The function has 2 (excl. $LATEST) versions:
        Version 1: env with testenv==staging
        Version 2: env with testenv==prod

        Alias A (Version == 1) has a routing config targeting both versions
        Alias B (Version == 1) has no routing config and simply is an alias for Version 1
        Alias C (Version == 2) has no routing config

        """
        function_name = f"alias-fn-{short_uid()}"
        snapshot.add_transformer(SortingTransformer("Aliases", lambda x: x["Name"]))

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Publish=True,
            Environment={"Variables": {"testenv": "staging"}},
        )
        snapshot.match("create_response", create_response)

        publish_v1 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v1", publish_v1)

        lambda_client.update_function_configuration(
            FunctionName=function_name, Environment={"Variables": {"testenv": "prod"}}
        )
        waiter = lambda_client.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        publish_v2 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v2", publish_v2)

        create_alias_1_1 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname1_1",
            FunctionVersion="1",
            Description="custom-alias",
            RoutingConfig={"AdditionalVersionWeights": {"2": 0.2}},
        )
        snapshot.match("create_alias_1_1", create_alias_1_1)
        get_alias_1_1 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname1_1")
        snapshot.match("get_alias_1_1", get_alias_1_1)

        create_alias_1_2 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname1_2",
            FunctionVersion="1",
            Description="custom-alias",
        )
        snapshot.match("create_alias_1_2", create_alias_1_2)
        get_alias_1_2 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname1_2")
        snapshot.match("get_alias_1_2", get_alias_1_2)

        create_alias_2 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname2",
            FunctionVersion="2",
            Description="custom-alias",
        )
        snapshot.match("create_alias_2", create_alias_2)
        get_alias_2 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname2")
        snapshot.match("get_alias_2", get_alias_2)

        # list_aliases can be optionally called with a FunctionVersion to filter only aliases for this version
        list_aliases_for_fnname = lambda_client.list_aliases(
            FunctionName=function_name
        )  # 3 aliases
        snapshot.match("list_aliases_for_fnname", list_aliases_for_fnname)
        assert len(list_aliases_for_fnname["Aliases"]) == 3

        list_aliases_for_version = lambda_client.list_aliases(
            FunctionName=function_name, FunctionVersion="1"
        )  # 2 aliases
        snapshot.match("list_aliases_for_version", list_aliases_for_version)
        assert len(list_aliases_for_version["Aliases"]) == 2

        delete_alias_response = lambda_client.delete_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("delete_alias_response", delete_alias_response)

        list_aliases_for_fnname_afterdelete = lambda_client.list_aliases(
            FunctionName=function_name
        )  # 2 aliases
        snapshot.match("list_aliases_for_fnname_afterdelete", list_aliases_for_fnname_afterdelete)

    def test_notfound_and_invalid_routingconfigs(
        self, create_boto_client, create_lambda_function_aws, snapshot, lambda_su_role
    ):
        lambda_client = create_boto_client(
            "lambda", additional_config=Config(parameter_validation=False)
        )
        function_name = f"alias-fn-{short_uid()}"

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Publish=True,
            Environment={"Variables": {"testenv": "staging"}},
        )
        snapshot.match("create_response", create_response)

        # create 2 versions
        publish_v1 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v1", publish_v1)

        lambda_client.update_function_configuration(
            FunctionName=function_name, Environment={"Variables": {"testenv": "prod"}}
        )
        waiter = lambda_client.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        publish_v2 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v2", publish_v2)

        # routing config with more than one entry (which isn't supported atm by AWS)
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"1": 0.8, "2": 0.2}},
            )
        snapshot.match("routing_config_exc_toomany", e.value.response)

        # value > 1
        with pytest.raises(ClientError) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": 2}},
            )
        snapshot.match("routing_config_exc_toohigh", e.value.response)

        # value < 0
        with pytest.raises(ClientError) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": -1}},
            )
        snapshot.match("routing_config_exc_subzero", e.value.response)

        # same version as alias pointer
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"1": 0.5}},
            )
        snapshot.match("routing_config_exc_sameversion", e.value.response)

        # function version 10 doesn't exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="10",
                RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
            )
        snapshot.match("routing_config_exc_version_doesnotexist", e.value.response)

        # function doesn't exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.create_alias(
                FunctionName=f"{function_name}-unknown",
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
            )
        snapshot.match("routing_config_exc_fn_doesnotexist", e.value.response)

        # empty routing config works fine
        create_alias_empty_routingconfig = lambda_client.create_alias(
            FunctionName=function_name,
            Name="custom-empty-routingconfig",
            FunctionVersion="1",
            RoutingConfig={"AdditionalVersionWeights": {}},
        )
        snapshot.match("create_alias_empty_routingconfig", create_alias_empty_routingconfig)

        # "normal scenario" works:
        create_alias_response = lambda_client.create_alias(
            FunctionName=function_name,
            Name="custom",
            FunctionVersion="1",
            RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
        )
        snapshot.match("create_alias_response", create_alias_response)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaTag:
    @pytest.fixture(scope="function")
    def fn_arn(self, create_lambda_function, lambda_client):
        """simple reusable setup to test tagging operations against"""
        function_name = f"fn-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        yield lambda_client.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    @pytest.mark.aws_validated
    def test_create_tag_on_fn_create(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"fn-{short_uid()}"
        custom_tag = f"tag-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(custom_tag, "<custom-tag>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"testtag": custom_tag},
        )
        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)
        fn_arn = get_function_result["Configuration"]["FunctionArn"]

        list_tags_result = lambda_client.list_tags(Resource=fn_arn)
        snapshot.match("list_tags_result", list_tags_result)

    @pytest.mark.aws_validated
    def test_tag_lifecycle(self, lambda_client, create_lambda_function, snapshot, fn_arn):

        # 1. add tag
        tag_single_response = lambda_client.tag_resource(Resource=fn_arn, Tags={"A": "tag-a"})
        snapshot.match("tag_single_response", tag_single_response)
        snapshot.match("tag_single_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 2. add multiple tags
        tag_multiple_response = lambda_client.tag_resource(
            Resource=fn_arn, Tags={"B": "tag-b", "C": "tag-c"}
        )
        snapshot.match("tag_multiple_response", tag_multiple_response)
        snapshot.match("tag_multiple_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 3. add overlapping tags
        tag_overlap_response = lambda_client.tag_resource(
            Resource=fn_arn, Tags={"C": "tag-c-newsuffix", "D": "tag-d"}
        )
        snapshot.match("tag_overlap_response", tag_overlap_response)
        snapshot.match("tag_overlap_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 3. remove tag
        untag_single_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("untag_single_response", untag_single_response)
        snapshot.match("untag_single_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 4. remove multiple tags
        untag_multiple_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["B", "C"])
        snapshot.match("untag_multiple_response", untag_multiple_response)
        snapshot.match("untag_multiple_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 5. try to remove only tags that don't exist
        untag_nonexisting_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["F"])
        snapshot.match("untag_nonexisting_response", untag_nonexisting_response)
        snapshot.match(
            "untag_nonexisting_response_listtags", lambda_client.list_tags(Resource=fn_arn)
        )

        # 6. remove a mix of tags that exist & don't exist
        untag_existing_and_nonexisting_response = lambda_client.untag_resource(
            Resource=fn_arn, TagKeys=["D", "F"]
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response", untag_existing_and_nonexisting_response
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response_listtags",
            lambda_client.list_tags(Resource=fn_arn),
        )

    @pytest.mark.aws_validated
    def test_tag_nonexisting_resource(self, lambda_client, snapshot, fn_arn):
        get_result = lambda_client.get_function(FunctionName=fn_arn)
        snapshot.match("pre_delete_get_function", get_result)
        lambda_client.delete_function(FunctionName=fn_arn)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.tag_resource(Resource=fn_arn, Tags={"A": "B"})
        snapshot.match("not_found_exception_tag", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("not_found_exception_untag", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_tags(Resource=fn_arn)
        snapshot.match("not_found_exception_list", e.value.response)


# some more common ones that usually don't work in the old provider
pytestmark = pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=[
        "$..Architectures",
        "$..EphemeralStorage",
        "$..LastUpdateStatus",
        "$..MemorySize",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
        "$..VpcConfig",
        "$..CodeSigningConfig",
        "$..Environment",  # missing
        "$..HTTPStatusCode",  # 201 vs 200
        "$..Layers",
    ],
)


class TestLambdaEventInvokeConfig:
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider, paths=["$..FunctionArn"])
    @pytest.mark.aws_validated
    def test_lambda_asynchronous_invocations(
        self,
        lambda_client,
        create_lambda_function,
        sqs_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
        cleanups,
    ):
        """Testing API actions of function event config"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        queue_arn = sqs_queue_arn(sqs_queue)
        destination_config = {
            "OnSuccess": {"Destination": queue_arn},
            "OnFailure": {"Destination": queue_arn},
        }

        # adding event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=123,
            DestinationConfig=destination_config,
        )
        cleanups.append(
            lambda: lambda_client.delete_function_event_invoke_config(FunctionName=function_name)
        )
        snapshot.match("put_function_event_invoke_config", response)

        # over writing event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            DestinationConfig=destination_config,
        )
        snapshot.match("put_function_event_invoke_config_overwritemaxeventage", response)

        # updating event invoke config
        response = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=1,
        )
        snapshot.match("put_function_event_invoke_config_maxattempt1", response)


class TestLambdaReservedConcurrency:

    # TODO: make this more robust & add snapshot
    @pytest.mark.skip(reason="very slow (only execute when needed)")
    @pytest.mark.aws_validated
    def test_lambda_provisioned_concurrency_doesnt_apply_to_latest(
        self, lambda_client, logs_client, create_lambda_function
    ):
        """create fn ⇒ publish version ⇒ provisioned concurrency @version ⇒ test if it applies to call to $LATEST"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        assert fn["State"] == "Active"

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        assert first_ver["State"] == "Active"
        assert fn["RevisionId"] != first_ver["RevisionId"]
        assert (
            lambda_client.get_function_configuration(
                FunctionName=func_name, Qualifier=first_ver["Version"]
            )["RevisionId"]
            == first_ver["RevisionId"]
        )

        # Normal published version without ProvisionedConcurrencyConfiguration
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create ProvisionedConcurrencyConfiguration for this Version
        versioned_revision_id_before = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name,
            Qualifier=first_ver["Version"],
            ProvisionedConcurrentExecutions=1,
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, first_ver["Version"]))
        versioned_revision_id_after = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        assert versioned_revision_id_before != versioned_revision_id_after
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )

        # $LATEST does *NOT* use provisioned concurrency
        assert get_invoke_init_type(lambda_client, func_name, "$LATEST") == "on-demand"
        # TODO: why is this flaky?
        # assert lambda_client.get_function(FunctionName=func_name, Qualifier='$LATEST')['Configuration']['RevisionId'] == lambda_client.get_function(FunctionName=func_name, Qualifier=first_ver['Version'])['Configuration']['RevisionId']

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        # TODO botocore.errorfactory.InvalidParameterValueException:
        #  An error occurred (InvalidParameterValueException) when calling the PutFunctionConcurrency operation: Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [50].
        response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_function_concurrency", response)
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", response)
        lambda_client.delete_function_concurrency(FunctionName=function_name)


class TestLambdaProvisionedConcurrency:
    @pytest.mark.skip(reason="very slow (only execute when needed)")
    @pytest.mark.aws_validated
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, lambda_client, logs_client, create_lambda_function, snapshot
    ):
        """
        create fn ⇒ publish version ⇒ create alias for version ⇒ put concurrency on alias
        ⇒ new version with change ⇒ change alias to new version ⇒ concurrency moves with alias? same behavior for calls to alias/version?
        """

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        snapshot.match("get-function-configuration", fn)

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)

        get_function_configuration = lambda_client.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", get_function_configuration)

        # There's no ProvisionedConcurrencyConfiguration yet
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = lambda_client.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_before_provisioned", get_function_result)
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, alias_name))
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        lambda_client.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(lambda_client, func_name))
        lambda_conf = lambda_client.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = lambda_client.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = lambda_client.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(lambda_client, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"
        assert (
            get_invoke_init_type(lambda_client, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(
            lambda_client.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        snapshot.match("provisioned_concurrency_notfound", e.value.response)


# API only functions (no lambda execution itself, i.e. no invoke)
@pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=["$..RevisionId", "$..Policy.Statement", "$..PolicyName", "$..PolicyArn", "$..Layers"],
)
class TestLambdaPermissions:
    @pytest.mark.aws_validated
    def test_add_lambda_permission_aws(
        self, lambda_client, iam_client, create_lambda_function, account_id, snapshot
    ):
        """Testing the add_permission call on lambda, by adding a new resource-based policy to a lambda function"""

        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        snapshot.match("create_lambda", lambda_create_response)
        # create lambda permission
        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission", resp)

        # fetch lambda policy
        get_policy_result = lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("get_policy", get_policy_result)

    @pytest.mark.skip_snapshot_verify(paths=["$..Message"], condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        permission_1_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
        )
        snapshot.match("add_permission_1", permission_1_add)

        sid_2 = "sqs"
        principal_2 = "sqs.amazonaws.com"
        permission_2_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid_2,
            Principal=principal_2,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission_2", permission_2_add)
        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)

        with pytest.raises(ClientError) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )
        snapshot.match("expect_error_remove_permission", e.value.response)

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid_2,
        )
        policy = json.loads(
            lambda_client.get_policy(
                FunctionName=function_name,
            )["Policy"]
        )
        snapshot.match("policy_after_removal", policy)

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
        )
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ctx:
            lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("expect_exception_get_policy", ctx.value.response)

    @pytest.mark.aws_validated
    def test_function_code_signing_config(self, lambda_client, create_lambda_function, snapshot):
        """Testing the API of code signing config"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        response = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{aws_stack.get_region()}:000000000000:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.match("create_code_signing_config", response)

        code_signing_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        response = lambda_client.update_code_signing_config(
            CodeSigningConfigArn=code_signing_arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
        snapshot.match("update_code_signing_config", response)

        response = lambda_client.get_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        snapshot.match("get_code_signing_config", response)

        response = lambda_client.put_function_code_signing_config(
            CodeSigningConfigArn=code_signing_arn, FunctionName=function_name
        )
        snapshot.match("put_function_code_signing_config", response)

        response = lambda_client.get_function_code_signing_config(FunctionName=function_name)
        snapshot.match("get_function_code_signing_config", response)

        response = lambda_client.delete_function_code_signing_config(FunctionName=function_name)
        snapshot.match("delete_function_code_signing_config", response)

        response = lambda_client.delete_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        snapshot.match("delete_code_signing_config", response)

    @pytest.mark.aws_validated
    def test_create_multiple_lambda_permissions(
        self, lambda_client, create_lambda_function, snapshot
    ):
        """Test creating multiple lambda permissions and checking the policy"""

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            runtime=Runtime.python3_7,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
        )

        action = "lambda:InvokeFunction"
        sid = "logs"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="logs.amazonaws.com",
        )
        snapshot.match("add_permission_response_1", resp)

        sid = "kinesis"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="kinesis.amazonaws.com",
        )
        snapshot.match("add_permission_response_2", resp)

        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)


class TestLambdaUrl:
    @pytest.mark.aws_validated
    def test_url_config_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", "lambda-url", reference_replacement=False)
        )

        function_name = f"test-function-{short_uid()}"

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_creation", ex.value.response)

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_handler.handler",
        )

        url_config_created = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("url_creation", url_config_created)

        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_duplication", ex.value.response)

        url_config_obtained = lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config", url_config_obtained)

        url_config_updated = lambda_client.update_function_url_config(
            FunctionName=function_name,
            AuthType="AWS_IAM",
        )
        snapshot.match("updated_url_config", url_config_updated)

        lambda_client.delete_function_url_config(FunctionName=function_name)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("failed_getter", ex.value.response)


class TestLambdaSizeLimits:
    def _generate_sized_python_str(self, filepath: str, size: int) -> str:
        """Generate a text of the specified size by appending #s at the end of the file"""
        with open(filepath, "r") as f:
            py_str = f.read()
        py_str += "#" * (size - len(py_str))
        return py_str

    @pytest.mark.aws_validated
    def test_oversized_lambda(self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot):
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, FUNCTION_MAX_UNZIPPED_SIZE
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @pytest.mark.aws_validated
    def test_large_lambda(
        self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot, cleanups
    ):
        function_name = f"test_lambda_{short_uid()}"
        cleanups.append(lambda: lambda_client.delete_function(FunctionName=function_name))
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, FUNCTION_MAX_UNZIPPED_SIZE - 1000
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        result = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("create_function_large_zip", result)
