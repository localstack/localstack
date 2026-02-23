import os

from localstack.testing.pytest import markers


def deploy_stack(deploy_cfn_template, template_filename, **kwargs):
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_filename)
    return deploy_cfn_template(template_path=template_path, **kwargs)


@markers.aws.validated
def test_update_loggroup_modify_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "loggroup_all_properties.yml")
    log_group_name = stack.outputs["LogGroupName"]
    log_group_arn = stack.outputs["LogGroupArn"]

    # Verify initial state
    result = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    group = [g for g in result["logGroups"] if g["logGroupName"] == log_group_name][0]
    snapshot.match("initial_retention", {"retentionInDays": group.get("retentionInDays")})

    tags = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)
    snapshot.match("initial_tags", tags)

    # Update
    deploy_stack(
        deploy_cfn_template,
        "loggroup_all_properties_variant.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    result = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    group = [g for g in result["logGroups"] if g["logGroupName"] == log_group_name][0]
    snapshot.match("updated_retention", {"retentionInDays": group.get("retentionInDays")})

    tags = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)
    snapshot.match("updated_tags", tags)

    snapshot.add_transformer(snapshot.transform.regex(log_group_arn, "<log-group-arn>"))


@markers.aws.validated
def test_update_loggroup_remove_optional_properties(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_stack(deploy_cfn_template, "loggroup_all_properties.yml")
    log_group_name = stack.outputs["LogGroupName"]
    log_group_arn = stack.outputs["LogGroupArn"]

    # Update to required only
    deploy_stack(
        deploy_cfn_template,
        "loggroup_required_only.yml",
        is_update=True,
        stack_name=stack.stack_name,
    )

    result = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    group = [g for g in result["logGroups"] if g["logGroupName"] == log_group_name][0]
    snapshot.match("after_remove_retention", {"retentionInDays": group.get("retentionInDays")})

    tags = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)
    snapshot.match("after_remove_tags", tags)

    snapshot.add_transformer(snapshot.transform.regex(log_group_arn, "<log-group-arn>"))
