from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from tests.integration.cloudformation.utils import load_template_raw


def test_create_record_set_via_id(
    route53_client,
    cfn_client,
    is_change_set_created_and_available,
    cleanup_changesets,
    cleanup_stacks,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    route53_name = f"www.{short_uid()}.com."
    caller_ref = f"caller-ref-{short_uid()}"
    create_zone_response = route53_client.create_hosted_zone(
        Name=route53_name, CallerReference=caller_ref
    )
    hosted_zone_id = create_zone_response["HostedZone"]["Id"]

    template_rendered = load_template_raw("route53_hostedzoneid_template.json")
    template_rendered = template_rendered % (hosted_zone_id, route53_name)
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )

    change_set_id = response["Id"]
    stack_id = response["StackId"]
    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))
        describe_result = cfn_client.describe_stacks(StackName=stack_id)
        assert describe_result["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


def test_create_record_set_via_name(
    route53_client,
    cfn_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    route53_name = f"www.{short_uid()}.com."
    caller_ref = f"caller-ref-{short_uid()}"
    route53_client.create_hosted_zone(Name=route53_name, CallerReference=caller_ref)

    template_rendered = load_template_raw("route53_hostedzonename_template.json")
    template_rendered = template_rendered % (route53_name, route53_name)
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )

    change_set_id = response["Id"]
    stack_id = response["StackId"]
    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))
        describe_result = cfn_client.describe_stacks(StackName=stack_id)
        assert describe_result["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
