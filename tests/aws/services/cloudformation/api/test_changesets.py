import os.path

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.cloudformation_utils import (
    load_template_file,
    load_template_raw,
    render_template,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import ShortCircuitWaitException, poll_condition, wait_until


@markers.aws.unknown
def test_create_change_set_without_parameters(
    cleanup_stacks, cleanup_changesets, is_change_set_created_and_available, aws_client
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )
    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw(template_path),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    try:
        # make sure the change set wasn't executed (which would create a topic)
        topics = aws_client.sns.list_topics()
        topic_arns = list(map(lambda x: x["TopicArn"], topics["Topics"]))
        assert not any("sns-topic-simple" in arn for arn in topic_arns)
        # stack is initially in REVIEW_IN_PROGRESS state. only after executing the change_set will it change its status
        stack_response = aws_client.cloudformation.describe_stacks(StackName=stack_id)
        assert stack_response["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS"

        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(
            is_change_set_created_and_available(change_set_id), 2, 10, strategy="exponential"
        )
        describe_response = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id
        )

        assert describe_response["ChangeSetName"] == change_set_name
        assert describe_response["ChangeSetId"] == change_set_id
        assert describe_response["StackId"] == stack_id
        assert describe_response["StackName"] == stack_name
        assert describe_response["ExecutionStatus"] == "AVAILABLE"
        assert describe_response["Status"] == "CREATE_COMPLETE"
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        assert changes[0]["ResourceChange"]["Action"] == "Add"
        assert changes[0]["ResourceChange"]["ResourceType"] == "AWS::SNS::Topic"
        assert changes[0]["ResourceChange"]["LogicalResourceId"] == "topic123"
    finally:
        cleanup_stacks([stack_id])
        cleanup_changesets([change_set_id])


# TODO: implement
@pytest.mark.xfail(condition=not is_aws_cloud(), reason="Not properly implemented")
@markers.aws.validated
def test_create_change_set_update_without_parameters(
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_change_set_finished,
    snapshot,
    aws_client,
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    """after creating a stack via a CREATE change set we send an UPDATE change set changing the SNS topic name"""
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    change_set_name2 = f"change-set-{short_uid()}"

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )

    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw(template_path),
        ChangeSetType="CREATE",
    )
    snapshot.match("create_change_set", response)
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    try:
        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(is_change_set_created_and_available(change_set_id))
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_change_set_finished(change_set_id))
        template = load_template_raw(template_path)

        update_response = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name2,
            TemplateBody=template.replace("sns-topic-simple", "sns-topic-simple-2"),
            ChangeSetType="UPDATE",
        )
        assert wait_until(is_change_set_created_and_available(update_response["Id"]))
        snapshot.match(
            "describe_change_set",
            aws_client.cloudformation.describe_change_set(ChangeSetName=update_response["Id"]),
        )
        snapshot.match(
            "list_change_set", aws_client.cloudformation.list_change_sets(StackName=stack_name)
        )

        describe_response = aws_client.cloudformation.describe_change_set(
            ChangeSetName=update_response["Id"]
        )
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        change = changes[0]["ResourceChange"]
        assert change["Action"] == "Modify"
        assert change["ResourceType"] == "AWS::SNS::Topic"
        assert change["LogicalResourceId"] == "topic123"
        assert "sns-topic-simple" in change["PhysicalResourceId"]
        assert change["Replacement"] == "True"
        assert "Properties" in change["Scope"]
        assert len(change["Details"]) == 1
        assert change["Details"][0]["Target"]["Name"] == "TopicName"
        assert change["Details"][0]["Target"]["RequiresRecreation"] == "Always"
    finally:
        cleanup_changesets(changesets=[change_set_id])
        cleanup_stacks(stacks=[stack_id])


@pytest.mark.skip(reason="TODO")
@markers.aws.unknown
def test_create_change_set_with_template_url():
    pass


@pytest.mark.xfail(reason="change set type not implemented")
@markers.aws.unknown
def test_create_change_set_create_existing(
    is_stack_created, cleanup_changesets, cleanup_stacks, aws_client
):
    """tries to create an already existing stack"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )
    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw(template_path),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id
    try:
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        with pytest.raises(Exception) as ex:
            change_set_name2 = f"change-set-{short_uid()}"
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName=change_set_name2,
                TemplateBody=load_template_raw("sns_topic_simple.yaml"),
                ChangeSetType="CREATE",
            )
        assert ex is not None
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@markers.aws.unknown
def test_create_change_set_update_nonexisting(aws_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )

    with pytest.raises(Exception) as ex:
        response = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_template_raw(template_path),
            ChangeSetType="UPDATE",
        )
        change_set_id = response["Id"]
        stack_id = response["StackId"]
        assert change_set_id
        assert stack_id
    err = ex.value.response["Error"]
    assert err["Code"] == "ValidationError"
    assert "does not exist" in err["Message"]


@pytest.mark.skip(reason="TODO")
@markers.aws.unknown
def test_create_change_set_import():
    """test importing existing resources into a stack via the change set"""
    pass  # TODO


@markers.aws.unknown
def test_create_change_set_invalid_params(aws_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )
    with pytest.raises(ClientError) as ex:
        aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_template_raw(template_path),
            ChangeSetType="INVALID",
        )
    err = ex.value.response["Error"]
    assert err["Code"] == "ValidationError"


@markers.aws.unknown
def test_create_change_set_missing_stackname(aws_client):
    """in this case boto doesn't even let us send the request"""
    change_set_name = f"change-set-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )
    with pytest.raises(Exception):
        aws_client.cloudformation.create_change_set(
            StackName="",
            ChangeSetName=change_set_name,
            TemplateBody=load_template_raw(template_path),
            ChangeSetType="CREATE",
        )


@markers.aws.validated
def test_create_change_set_with_ssm_parameter(
    cleanup_changesets,
    cleanup_stacks,
    is_change_set_created_and_available,
    is_stack_created,
    aws_client,
):
    """References a simple stack parameter"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_name = f"ls-param-{short_uid()}"
    parameter_value = f"ls-param-value-{short_uid()}"
    sns_topic_logical_id = "topic123"
    parameter_logical_id = "parameter123"

    aws_client.ssm.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/dynamicparameter_ssm_string.yaml"
    )
    template_rendered = render_template(
        load_template_raw(template_path), parameter_name=parameter_name
    )
    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    try:
        # make sure the change set wasn't executed (which would create a new topic)
        list_topics_response = aws_client.sns.list_topics()
        matching_topics = [
            t for t in list_topics_response["Topics"] if parameter_value in t["TopicArn"]
        ]
        assert matching_topics == []

        # stack is initially in REVIEW_IN_PROGRESS state. only after executing the change_set will it change its status
        stack_response = aws_client.cloudformation.describe_stacks(StackName=stack_id)
        assert stack_response["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS"

        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(is_change_set_created_and_available(change_set_id))
        describe_response = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id
        )

        assert describe_response["ChangeSetName"] == change_set_name
        assert describe_response["ChangeSetId"] == change_set_id
        assert describe_response["StackId"] == stack_id
        assert describe_response["StackName"] == stack_name
        assert describe_response["ExecutionStatus"] == "AVAILABLE"
        assert describe_response["Status"] == "CREATE_COMPLETE"
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        assert changes[0]["ResourceChange"]["Action"] == "Add"
        assert changes[0]["ResourceChange"]["ResourceType"] == "AWS::SNS::Topic"
        assert changes[0]["ResourceChange"]["LogicalResourceId"] == sns_topic_logical_id

        parameters = describe_response["Parameters"]
        assert len(parameters) == 1
        assert parameters[0]["ParameterKey"] == parameter_logical_id
        assert parameters[0]["ParameterValue"] == parameter_name
        assert parameters[0]["ResolvedValue"] == parameter_value  # the important part

        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))

        topics = aws_client.sns.list_topics()
        topic_arns = list(map(lambda x: x["TopicArn"], topics["Topics"]))
        assert any((parameter_value in t) for t in topic_arns)
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@markers.aws.validated
def test_describe_change_set_nonexisting(snapshot, aws_client):
    with pytest.raises(Exception) as ex:
        aws_client.cloudformation.describe_change_set(
            StackName="somestack", ChangeSetName="DoesNotExist"
        )
    snapshot.match("exception", ex.value)


@pytest.mark.skip(reason="fails because of the properties mutation in the result_handler")
@markers.aws.unknown
def test_execute_change_set(
    is_change_set_finished,
    is_change_set_created_and_available,
    is_change_set_failed_and_unavailable,
    cleanup_changesets,
    cleanup_stacks,
    aws_client,
):
    """check if executing a change set succeeds in creating/modifying the resources in changed"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
    )
    template_body = load_template_raw(template_path)

    response = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_body,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    try:
        assert wait_until(is_change_set_created_and_available(change_set_id=change_set_id))
        aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        assert wait_until(is_change_set_finished(change_set_id))
        # check if stack resource was created
        topics = aws_client.sns.list_topics()
        topic_arns = list(map(lambda x: x["TopicArn"], topics["Topics"]))
        assert any(("sns-topic-simple" in t) for t in topic_arns)

        # new change set name
        change_set_name = f"change-set-{short_uid()}"
        # check if update with identical stack leads to correct behavior
        response = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=template_body,
            ChangeSetType="UPDATE",
        )
        change_set_id = response["Id"]
        stack_id = response["StackId"]
        assert wait_until(is_change_set_failed_and_unavailable(change_set_id=change_set_id))
        describe_failed_change_set_result = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id
        )
        assert describe_failed_change_set_result["ChangeSetName"] == change_set_name
        assert (
            describe_failed_change_set_result["StatusReason"]
            == "The submitted information didn't contain changes. Submit different information to create a change set."
        )
        with pytest.raises(ClientError) as e:
            aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        e.match("InvalidChangeSetStatus")
        e.match(
            rf"ChangeSet \[{change_set_id}\] cannot be executed in its current status of \[FAILED\]"
        )
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@markers.aws.validated
def test_delete_change_set_exception(snapshot, aws_client):
    """test error cases when trying to delete a change set"""
    with pytest.raises(Exception) as e1:
        aws_client.cloudformation.delete_change_set(
            StackName="nostack", ChangeSetName="DoesNotExist"
        )
    snapshot.match("e1", e1)

    with pytest.raises(Exception) as e2:
        aws_client.cloudformation.delete_change_set(ChangeSetName="DoesNotExist")
    snapshot.match("e2", e2)


@markers.aws.validated
def test_create_and_then_remove_non_supported_resource_change_set(deploy_cfn_template):
    # first deploy cfn with a CodeArtifact resource that is not actually supported
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/code_artifact_template.yaml"
    )
    template_body = load_template_raw(template_path)
    stack = deploy_cfn_template(
        template=template_body,
        parameters={"CADomainName": f"domainname-{short_uid()}"},
    )

    # removal of CodeArtifact should not throw exception
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/code_artifact_remove_template.yaml"
    )
    template_body = load_template_raw(template_path)
    deploy_cfn_template(
        is_update=True,
        template=template_body,
        stack_name=stack.stack_name,
    )


@markers.aws.validated
def test_create_and_then_update_refreshes_template_metadata(
    aws_client,
    cleanup_changesets,
    cleanup_stacks,
    is_change_set_finished,
    is_change_set_created_and_available,
):
    stacks_to_cleanup = set()
    changesets_to_cleanup = set()

    try:
        stack_name = f"stack-{short_uid()}"

        template_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
        )

        template_body = load_template_raw(template_path)

        create_response = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=f"change-set-{short_uid()}",
            TemplateBody=template_body,
            ChangeSetType="CREATE",
        )

        stacks_to_cleanup.add(create_response["StackId"])
        changesets_to_cleanup.add(create_response["Id"])

        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=create_response["Id"]
        )

        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=create_response["Id"]
        )

        wait_until(is_change_set_finished(create_response["Id"]))

        # Note the metadata alone won't change if there are no changes to resources
        # TODO: find a better way to make a replacement in yaml template
        template_body = template_body.replace(
            "TopicName: sns-topic-simple",
            "TopicName: sns-topic-simple-updated",
        )

        update_response = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=f"change-set-{short_uid()}",
            TemplateBody=template_body,
            ChangeSetType="UPDATE",
        )

        stacks_to_cleanup.add(update_response["StackId"])
        changesets_to_cleanup.add(update_response["Id"])

        wait_until(is_change_set_created_and_available(update_response["Id"]))

        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=update_response["Id"]
        )

        wait_until(is_change_set_finished(update_response["Id"]))

        summary = aws_client.cloudformation.get_template_summary(StackName=stack_name)

        assert "TopicName" in summary["Metadata"]
        assert "sns-topic-simple-updated" in summary["Metadata"]
    finally:
        cleanup_stacks(list(stacks_to_cleanup))
        cleanup_changesets(list(changesets_to_cleanup))


# TODO: the intention of this test is not particularly clear. The resource isn't removed, it'll just generate a new bucket with a new default name
# TODO: rework this to a conditional instead of two templates + parameter usage instead of templating
@markers.aws.validated
def test_create_and_then_remove_supported_resource_change_set(deploy_cfn_template, aws_client):
    first_bucket_name = f"test-bucket-1-{short_uid()}"
    second_bucket_name = f"test-bucket-2-{short_uid()}"
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/for_removal_setup.yaml"
    )
    template_body = load_template_raw(template_path)

    stack = deploy_cfn_template(
        template=template_body,
        template_mapping={
            "first_bucket_name": first_bucket_name,
            "second_bucket_name": second_bucket_name,
        },
    )
    assert first_bucket_name in stack.outputs["FirstBucket"]
    assert second_bucket_name in stack.outputs["SecondBucket"]

    available_buckets = aws_client.s3.list_buckets()
    bucket_names = [bucket["Name"] for bucket in available_buckets["Buckets"]]
    assert first_bucket_name in bucket_names
    assert second_bucket_name in bucket_names

    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/for_removal_remove.yaml"
    )
    template_body = load_template_raw(template_path)
    stack_updated = deploy_cfn_template(
        is_update=True,
        template=template_body,
        template_mapping={"first_bucket_name": first_bucket_name},
        stack_name=stack.stack_name,
    )

    assert first_bucket_name in stack_updated.outputs["FirstBucket"]

    def assert_bucket_gone():
        available_buckets = aws_client.s3.list_buckets()
        bucket_names = [bucket["Name"] for bucket in available_buckets["Buckets"]]
        return first_bucket_name in bucket_names and second_bucket_name not in bucket_names

    poll_condition(condition=assert_bucket_gone, timeout=20, interval=5)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..NotificationARNs",
        "$..IncludeNestedStacks",
        "$..Parameters",
    ]
)
@markers.aws.validated
def test_empty_changeset(snapshot, cleanups, aws_client):
    """
    Creates a change set that doesn't actually update any resources and then tries to execute it
    """
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    change_set_name_nochange = f"change-set-nochange-{short_uid()}"
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

    template_path = os.path.join(os.path.dirname(__file__), "../../../templates/cdkmetadata.yaml")
    template = load_template_file(template_path)

    # 1. create change set and execute

    first_changeset = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetType="CREATE",
    )
    snapshot.match("first_changeset", first_changeset)

    def _check_changeset_available():
        status = aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=first_changeset["Id"]
        )["Status"]
        if status == "FAILED":
            raise ShortCircuitWaitException("Change set in unrecoverable status")
        return status == "CREATE_COMPLETE"

    assert wait_until(_check_changeset_available)

    describe_first_cs = aws_client.cloudformation.describe_change_set(
        StackName=stack_name, ChangeSetName=first_changeset["Id"]
    )
    snapshot.match("describe_first_cs", describe_first_cs)
    assert describe_first_cs["ExecutionStatus"] == "AVAILABLE"

    aws_client.cloudformation.execute_change_set(
        StackName=stack_name, ChangeSetName=first_changeset["Id"]
    )

    def _check_changeset_success():
        status = aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=first_changeset["Id"]
        )["ExecutionStatus"]
        if status in ["EXECUTE_FAILED", "UNAVAILABLE", "OBSOLETE"]:
            raise ShortCircuitWaitException("Change set in unrecoverable status")
        return status == "EXECUTE_COMPLETE"

    assert wait_until(_check_changeset_success)

    # 2. create a new change set without changes
    nochange_changeset = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name_nochange,
        TemplateBody=template,
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetType="UPDATE",
    )
    snapshot.match("nochange_changeset", nochange_changeset)

    describe_nochange = aws_client.cloudformation.describe_change_set(
        StackName=stack_name, ChangeSetName=nochange_changeset["Id"]
    )
    snapshot.match("describe_nochange", describe_nochange)
    assert describe_nochange["ExecutionStatus"] == "UNAVAILABLE"

    # 3. try to execute the unavailable change set
    with pytest.raises(aws_client.cloudformation.exceptions.InvalidChangeSetStatusException) as e:
        aws_client.cloudformation.execute_change_set(
            StackName=stack_name, ChangeSetName=nochange_changeset["Id"]
        )
    snapshot.match("error_execute_failed", e.value)


@markers.aws.validated
def test_deleted_changeset(snapshot, cleanups, aws_client):
    """simple case verifying that proper exception is thrown when trying to get a deleted changeset"""
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    changeset_name = f"changeset-{short_uid()}"
    stack_name = f"stack-{short_uid()}"
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

    snapshot.add_transformer(snapshot.transform.regex(stack_name, "<stack-name>"))

    template_path = os.path.join(os.path.dirname(__file__), "../../../templates/cdkmetadata.yaml")
    template = load_template_file(template_path)

    # 1. create change set
    create = aws_client.cloudformation.create_change_set(
        ChangeSetName=changeset_name,
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ChangeSetType="CREATE",
    )
    snapshot.match("create", create)

    changeset_id = create["Id"]

    def _check_changeset_available():
        status = aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=changeset_id
        )["Status"]
        if status == "FAILED":
            raise ShortCircuitWaitException("Change set in unrecoverable status")
        return status == "CREATE_COMPLETE"

    assert wait_until(_check_changeset_available)

    # 2. delete change set
    aws_client.cloudformation.delete_change_set(ChangeSetName=changeset_id, StackName=stack_name)

    with pytest.raises(aws_client.cloudformation.exceptions.ChangeSetNotFoundException) as e:
        aws_client.cloudformation.describe_change_set(
            StackName=stack_name, ChangeSetName=changeset_id
        )
    snapshot.match("postdelete_changeset_notfound", e.value)


@markers.aws.validated
def test_autoexpand_capability_requirement(cleanups, aws_client):
    stack_name = f"test-stack-{short_uid()}"
    changeset_name = f"test-changeset-{short_uid()}"
    queue_name = f"test-queue-{short_uid()}"
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

    template_body = load_template_raw(
        os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_macro_languageextensions.yaml"
        )
    )

    with pytest.raises(aws_client.cloudformation.exceptions.InsufficientCapabilitiesException):
        # requires the capability
        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[
                {"ParameterKey": "QueueList", "ParameterValue": "faa,fbb,fcc"},
                {"ParameterKey": "QueueNameParam", "ParameterValue": queue_name},
            ],
        )

    # does not require the capability
    create_changeset_result = aws_client.cloudformation.create_change_set(
        StackName=stack_name,
        ChangeSetName=changeset_name,
        TemplateBody=template_body,
        ChangeSetType="CREATE",
        Parameters=[
            {"ParameterKey": "QueueList", "ParameterValue": "faa,fbb,fcc"},
            {"ParameterKey": "QueueNameParam", "ParameterValue": queue_name},
        ],
    )
    aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
        ChangeSetName=create_changeset_result["Id"]
    )
