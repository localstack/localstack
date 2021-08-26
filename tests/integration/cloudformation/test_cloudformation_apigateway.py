import jinja2

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_cfn_apigateway_aws_integration(
    cfn_client,
    apigateway_client,
    s3_client,
    iam_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
):
    api_name = f"rest-api-{short_uid()}"
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    template_rendered = jinja2.Template(
        load_template_raw("apigw-awsintegration-request-parameters.yaml")
    ).render(api_name=api_name)
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

        apis = [
            api for api in apigateway_client.get_rest_apis()["items"] if api["name"] == api_name
        ]
        assert len(apis) == 1
        api_id = apis[0]["id"]

        resources = apigateway_client.get_resources(restApiId=api_id)["items"]
        assert (
            resources[0]["resourceMethods"]["GET"]["requestParameters"]["method.request.path.id"]
            is False
        )
        assert (
            resources[0]["resourceMethods"]["GET"]["methodIntegration"]["requestParameters"][
                "integration.request.path.object"
            ]
            == "method.request.path.id"
        )
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
