import jinja2

from localstack import constants
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw
from tests.integration.fixtures import only_localstack


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

        # check resources creation
        apis = [
            api for api in apigateway_client.get_rest_apis()["items"] if api["name"] == api_name
        ]
        assert len(apis) == 1
        api_id = apis[0]["id"]

        # check resources creation
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

        # check domains creation
        domain_names = [
            domain["domainName"] for domain in apigateway_client.get_domain_names()["items"]
        ]
        expected_domain = "cfn5632.localstack.cloud"  # hardcoded value from template yaml file
        assert expected_domain in domain_names

        # check basepath mappings creation
        mappings = [
            mapping["basePath"]
            for mapping in apigateway_client.get_base_path_mappings(domainName=expected_domain)[
                "items"
            ]
        ]
        assert len(mappings) == 1
        assert mappings[0] == "(none)"
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])


@only_localstack
def test_url_output(
    cfn_client,
    apigateway_client,
    is_change_set_created_and_available,
    is_stack_created,
    cleanup_changesets,
    cleanup_stacks,
    tmp_http_server,
):
    test_port, invocations, proxy = tmp_http_server
    integration_uri = f"http://localhost:{test_port}/{{proxy}}"
    api_name = f"rest-api-{short_uid()}"
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("apigateway-url-output.yaml")).render(
        api_name=api_name, integration_uri=integration_uri
    )
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

        describe_response = cfn_client.describe_stacks(StackName=stack_id)
        outputs = describe_response["Stacks"][0]["Outputs"]
        assert len(outputs) == 2
        api_id = [o["OutputValue"] for o in outputs if o["OutputKey"] == "ApiV1IdOutput"][0]
        api_url = [o["OutputValue"] for o in outputs if o["OutputKey"] == "ApiV1UrlOutput"][0]
        assert api_id
        assert api_url
        assert api_id in api_url

        assert f"https://{api_id}.execute-api.{constants.LOCALHOST_HOSTNAME}:4566" in api_url

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
