import json

import pytest
import requests
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_deployment,
    create_rest_api_integration,
    create_rest_api_stage,
    create_rest_resource_method,
)
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_AWS_PROXY


class TestApiGatewayCommon:
    """
    In this class we won't test individual CRUD API calls but how those will affect the integrations and
    requests/responses from the API.
    """

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.invalid-request-body.Type",
        ]
    )
    def test_api_gateway_request_validator(
        self, create_lambda_function, create_rest_apigw, apigw_redeploy_api, snapshot, aws_client
    ):
        # TODO: create fixture which will provide basic integrations where we can test behaviour
        # see once we have more cases how we can regroup functionality into one or several fixtures
        # example: create a basic echo lambda + integrations + deploy stage
        # We could also leverage the MOCK integration
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestValidatorId"),
                snapshot.transform.key_value("cacheNamespace"),
                snapshot.transform.key_value("id"),  # deployment id
                snapshot.transform.key_value("fn_name"),  # lambda name
                snapshot.transform.key_value("fn_arn"),  # lambda arn
            ]
        )

        fn_name = f"test-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_LAMBDA_AWS_PROXY,
            runtime=Runtime.python3_9,
        )
        lambda_arn = aws_client.lambda_.get_function(FunctionName=fn_name)["Configuration"][
            "FunctionArn"
        ]
        # matching on lambda id for reference replacement in snapshots
        snapshot.match("register-lambda", {"fn_name": fn_name, "fn_arn": lambda_arn})

        parsed_arn = parse_arn(lambda_arn)
        region = parsed_arn["region"]
        account_id = parsed_arn["account"]

        api_id, _, root = create_rest_apigw(name="aws lambda api")

        resource_1 = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root, pathPart="test"
        )["id"]

        resource_id = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=resource_1, pathPart="{test}"
        )["id"]

        validator_id = aws_client.apigateway.create_request_validator(
            restApiId=api_id,
            name="test-validator",
            validateRequestParameters=True,
            validateRequestBody=True,
        )["id"]

        for http_method in ("GET", "POST"):
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                authorizationType="NONE",
                requestValidatorId=validator_id,
                requestParameters={"method.request.path.test": True},
            )

            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                integrationHttpMethod="POST",
                type="AWS_PROXY",
                uri=f"arn:aws:apigateway:{region}:lambda:path//2015-03-31/functions/"
                f"{lambda_arn}/invocations",
            )
            aws_client.apigateway.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
            )
            aws_client.apigateway.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
            )

        stage_name = "local"
        deploy_1 = aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
        snapshot.match("deploy-1", deploy_1)

        source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*/test/*"

        aws_client.lambda_.add_permission(
            FunctionName=lambda_arn,
            StatementId=str(short_uid()),
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )

        url = api_invoke_url(api_id, stage=stage_name, path="/test/value")
        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.ok

        response = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {
                    "op": "add",
                    "path": "/requestParameters/method.request.path.issuer",
                    "value": "true",
                },
                {
                    "op": "remove",
                    "path": "/requestParameters/method.request.path.test",
                    "value": "true",
                },
            ],
        )
        snapshot.match("change-request-path-names", response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        response = requests.post(url, json={"test": "test"})
        # FIXME: for now, not implemented in LocalStack, we don't validate RequestParameters yet
        # assert response.status_code == 400
        if response.status_code == 400:
            snapshot.match("missing-required-request-params", response.json())

        # create Model schema to validate body
        aws_client.apigateway.create_model(
            restApiId=api_id,
            name="testSchema",
            contentType="application/json",
            schema=json.dumps(
                {
                    "title": "testSchema",
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                    },
                    "required": ["a", "b"],
                }
            ),
        )
        # then attach the schema to the methods
        for http_method in ("GET", "POST"):
            response = aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                patchOperations=[
                    {
                        "op": "add",
                        "path": "/requestModels/application~1json",
                        "value": "testSchema",
                    },
                ],
            )
            snapshot.match(f"add-schema-{http_method}", response)

        # revert the path validation for POST method
        response = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {
                    "op": "add",
                    "path": "/requestParameters/method.request.path.test",
                    "value": "true",
                },
                {
                    "op": "remove",
                    "path": "/requestParameters/method.request.path.issuer",
                    "value": "true",
                },
            ],
        )
        snapshot.match("revert-request-path-names", response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        # the validator should then check against this schema and fail
        response = requests.post(url, json={"test": "test"})
        assert response.status_code == 400
        snapshot.match("invalid-request-body", response.json())

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.status_code == 400

        # GET request with an empty body, content type JSON
        response_get = requests.get(url, headers={"Content-Type": "application/json"})
        assert response_get.status_code == 400

        # remove the validator from the methods
        for http_method in ("GET", "POST"):
            response = aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/requestValidatorId",
                        "value": "",
                    },
                ],
            )
            snapshot.match(f"remove-validator-{http_method}", response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.ok


class TestUsagePlans:
    @markers.aws.validated
    def test_api_key_required_for_methods(
        self,
        aws_client,
        snapshot,
        create_rest_apigw,
        apigw_redeploy_api,
    ):
        snapshot.add_transformer(snapshot.transform.apigateway_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("apiId"),
                snapshot.transform.key_value("value"),
            ]
        )

        # Create a REST API with the apiKeySource set to "HEADER"
        api_id, _, root_id = create_rest_apigw(name="test API key", apiKeySource="HEADER")

        resource = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )

        resource_id = resource["id"]

        aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            authorizationType="NONE",
            apiKeyRequired=True,
        )

        aws_client.apigateway.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
        )

        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            integrationHttpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )

        aws_client.apigateway.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            selectionPattern="",
        )

        stage_name = "dev"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

        usage_plan_response = aws_client.apigateway.create_usage_plan(
            name=f"test-plan-{short_uid()}",
            description="Test Usage Plan for API key",
            quota={"limit": 10, "period": "DAY", "offset": 0},
            throttle={"rateLimit": 2, "burstLimit": 1},
            apiStages=[{"apiId": api_id, "stage": stage_name}],
            tags={"tag_key": "tag_value"},
        )
        snapshot.match("create-usage-plan", usage_plan_response)

        usage_plan_id = usage_plan_response["id"]

        key_name = f"testApiKey-{short_uid()}"
        api_key_response = aws_client.apigateway.create_api_key(
            name=key_name,
            enabled=True,
        )
        snapshot.match("create-api-key", api_key_response)
        api_key_id = api_key_response["id"]

        create_usage_plan_key_resp = aws_client.apigateway.create_usage_plan_key(
            usagePlanId=usage_plan_id,
            keyId=api_key_id,
            keyType="API_KEY",
        )
        snapshot.match("create-usage-plan-key", create_usage_plan_key_resp)

        url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")
        response = requests.get(url)
        # when the api key is not passed as part of the header
        assert response.status_code == 403

        def _assert_with_key(expected_status_code: int):
            _response = requests.get(url, headers={"x-api-key": api_key_response["value"]})
            assert _response.status_code == expected_status_code

        # AWS takes a very, very long time to make the key enabled
        retries = 10 if is_aws_cloud() else 3
        sleep = 12 if is_aws_cloud() else 1
        retry(_assert_with_key, retries=retries, sleep=sleep, expected_status_code=200)

        # now disable the key to verify that we should not be able to access the api
        patch_operations = [
            {"op": "replace", "path": "/enabled", "value": "false"},
        ]
        response = aws_client.apigateway.update_api_key(
            apiKey=api_key_id, patchOperations=patch_operations
        )
        snapshot.match("update-api-key-disabled", response)

        retry(_assert_with_key, retries=retries, sleep=sleep, expected_status_code=403)

    @markers.aws.validated
    def test_usage_plan_crud(self, create_rest_apigw, snapshot, aws_client, echo_http_server_post):
        snapshot.add_transformer(snapshot.transform.key_value("id", reference_replacement=True))
        snapshot.add_transformer(snapshot.transform.key_value("name"))
        snapshot.add_transformer(snapshot.transform.key_value("description"))
        snapshot.add_transformer(snapshot.transform.key_value("apiId", reference_replacement=True))

        # clean up any existing usage plans
        old_usage_plans = aws_client.apigateway.get_usage_plans().get("items", [])
        for usage_plan in old_usage_plans:
            aws_client.apigateway.delete_usage_plan(usagePlanId=usage_plan["id"])

        api_id, _, root = create_rest_apigw(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )

        create_rest_resource_method(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=root,
            httpMethod="GET",
            authorizationType="none",
        )

        create_rest_api_integration(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=root,
            httpMethod="GET",
            integrationHttpMethod="POST",
            type="HTTP",
            uri=echo_http_server_post,
        )

        deployment_id, _ = create_rest_api_deployment(aws_client.apigateway, restApiId=api_id)
        stage = create_rest_api_stage(
            aws_client.apigateway, restApiId=api_id, stageName="dev", deploymentId=deployment_id
        )

        # create usage plan
        response = aws_client.apigateway.create_usage_plan(
            name=f"test-usage-plan-{short_uid()}",
            description="this is my usage plan",
            apiStages=[
                {"apiId": api_id, "stage": stage},
            ],
        )
        snapshot.match("create-usage-plan", response)
        usage_plan_id = response["id"]

        # get usage plan
        response = aws_client.apigateway.get_usage_plan(usagePlanId=usage_plan_id)
        snapshot.match("get-usage-plan", response)

        # get usage plans
        response = aws_client.apigateway.get_usage_plans()
        snapshot.match("get-usage-plans", response)

        # update usage plan
        response = aws_client.apigateway.update_usage_plan(
            usagePlanId=usage_plan_id,
            patchOperations=[
                {"op": "replace", "path": "/throttle/burstLimit", "value": "100"},
                {"op": "replace", "path": "/throttle/rateLimit", "value": "200"},
            ],
        )
        snapshot.match("update-usage-plan", response)


class TestDocumentations:
    @markers.aws.validated
    def test_documentation_parts_and_versions(
        self, aws_client, create_rest_apigw, apigw_add_transformers, snapshot
    ):
        client = aws_client.apigateway

        # create API
        api_id, api_name, root_id = create_rest_apigw()

        # create documentation part
        response = client.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties=json.dumps({"foo": "bar"}),
        )
        snapshot.match("create-part-response", response)

        response = client.get_documentation_parts(restApiId=api_id)
        snapshot.match("get-parts-response", response)

        # create/update/get documentation version

        response = client.create_documentation_version(
            restApiId=api_id, documentationVersion="v123"
        )
        snapshot.match("create-version-response", response)

        response = client.update_documentation_version(
            restApiId=api_id,
            documentationVersion="v123",
            patchOperations=[{"op": "replace", "path": "/description", "value": "doc version new"}],
        )
        snapshot.match("update-version-response", response)

        response = client.get_documentation_version(restApiId=api_id, documentationVersion="v123")
        snapshot.match("get-version-response", response)


class TestStages:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..createdDate", "$..lastUpdatedDate"])
    def test_create_update_stages(
        self, aws_client, create_rest_apigw, apigw_add_transformers, snapshot
    ):
        client = aws_client.apigateway

        # create API, method, integration, deployment
        api_id, api_name, root_id = create_rest_apigw()
        client.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
        )
        client.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
        response = client.create_deployment(restApiId=api_id)
        deployment_id = response["id"]

        # create documentation
        client.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties=json.dumps({"foo": "bar"}),
        )
        client.create_documentation_version(restApiId=api_id, documentationVersion="v123")

        # create stage
        response = client.create_stage(
            restApiId=api_id,
            stageName="s1",
            deploymentId=deployment_id,
            description="my stage",
            documentationVersion="v123",
        )
        snapshot.match("create-stage", response)

        # negative tests for immutable/non-updateable attributes

        with pytest.raises(ClientError) as ctx:
            client.update_stage(
                restApiId=api_id,
                stageName="s1",
                patchOperations=[
                    {"op": "replace", "path": "/documentation_version", "value": "123"}
                ],
            )
        snapshot.match("error-update-doc-version", ctx.value.response)

        with pytest.raises(ClientError) as ctx:
            client.update_stage(
                restApiId=api_id,
                stageName="s1",
                patchOperations=[
                    {"op": "replace", "path": "/tags/tag1", "value": "value1"},
                ],
            )
        snapshot.match("error-update-tags", ctx.value.response)

        # update & get stage
        response = client.update_stage(
            restApiId=api_id,
            stageName="s1",
            patchOperations=[
                {"op": "replace", "path": "/description", "value": "stage new"},
                {"op": "replace", "path": "/variables/var1", "value": "test"},
                {"op": "replace", "path": "/variables/var2", "value": "test2"},
                {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "123"},
                {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
                {"op": "replace", "path": "/tracingEnabled", "value": "true"},
                {"op": "replace", "path": "/test/GET/throttling/burstLimit", "value": "124"},
            ],
        )
        snapshot.match("update-stage", response)

        response = client.get_stage(restApiId=api_id, stageName="s1")
        snapshot.match("get-stage", response)

        # show that updating */* does not override previously set values, only provides default values then like shown
        # above
        response = client.update_stage(
            restApiId=api_id,
            stageName="s1",
            patchOperations=[
                {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "100"},
            ],
        )
        snapshot.match("update-stage-override", response)


class TestDeployments:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..createdDate", "$..lastUpdatedDate"])
    @pytest.mark.parametrize("create_stage_manually", [True, False])
    def test_create_delete_deployments(
        self, create_stage_manually, aws_client, create_rest_apigw, apigw_add_transformers, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.apigateway_api())
        client = aws_client.apigateway

        # create API, method, integration, deployment
        api_id, _, root_id = create_rest_apigw()
        client.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
        )
        client.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

        # create deployment - stage can be passed as parameter, or created separately below
        kwargs = {} if create_stage_manually else {"stageName": "s1"}
        response = client.create_deployment(restApiId=api_id, **kwargs)
        deployment_id = response["id"]

        # create stage
        if create_stage_manually:
            client.create_stage(restApiId=api_id, stageName="s1", deploymentId=deployment_id)

        # get deployment and stages
        response = client.get_deployment(restApiId=api_id, deploymentId=deployment_id)
        snapshot.match("get-deployment", response)
        response = client.get_stages(restApiId=api_id)
        snapshot.match("get-stages", response)

        for i in range(3):
            # asset that deleting the deployment fails if stage exists
            with pytest.raises(ClientError) as ctx:
                client.delete_deployment(restApiId=api_id, deploymentId=deployment_id)
            snapshot.match(f"delete-deployment-error-{i}", ctx.value.response)

            # delete stage and deployment
            client.delete_stage(restApiId=api_id, stageName="s1")
            client.delete_deployment(restApiId=api_id, deploymentId=deployment_id)

            # re-create stage and deployment
            response = client.create_deployment(restApiId=api_id, **kwargs)
            deployment_id = response["id"]
            if create_stage_manually:
                client.create_stage(restApiId=api_id, stageName="s1", deploymentId=deployment_id)

            # list deployments and stages again
            response = client.get_deployments(restApiId=api_id)
            snapshot.match(f"get-deployments-{i}", response)
            response = client.get_stages(restApiId=api_id)
            snapshot.match(f"get-stages-{i}", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..createdDate", "$..lastUpdatedDate"])
    def test_create_update_deployments(
        self, aws_client, create_rest_apigw, apigw_add_transformers, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.apigateway_api())
        client = aws_client.apigateway

        # create API, method, integration, deployment
        api_id, _, root_id = create_rest_apigw()
        client.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
        )
        client.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")

        # create deployment - stage can be passed as parameter, or created separately below
        response = client.create_deployment(restApiId=api_id)
        deployment_id_1 = response["id"]

        # create stage
        client.create_stage(restApiId=api_id, stageName="s1", deploymentId=deployment_id_1)

        # get deployment and stages
        response = client.get_deployment(restApiId=api_id, deploymentId=deployment_id_1)
        snapshot.match("get-deployment-1", response)
        response = client.get_stages(restApiId=api_id)
        snapshot.match("get-stages", response)

        # asset that deleting the deployment fails if stage exists
        with pytest.raises(ClientError) as ctx:
            client.delete_deployment(restApiId=api_id, deploymentId=deployment_id_1)
        snapshot.match("delete-deployment-error", ctx.value.response)

        # create another deployment with the previous stage, which should update the stage
        response = client.create_deployment(restApiId=api_id, stageName="s1")
        deployment_id_2 = response["id"]

        # get deployments and stages
        response = client.get_deployment(restApiId=api_id, deploymentId=deployment_id_1)
        snapshot.match("get-deployment-1-after-update", response)
        response = client.get_deployment(restApiId=api_id, deploymentId=deployment_id_2)
        snapshot.match("get-deployment-2", response)
        response = client.get_stages(restApiId=api_id)
        snapshot.match("get-stages-after-update", response)

        response = client.delete_deployment(restApiId=api_id, deploymentId=deployment_id_1)
        snapshot.match("delete-deployment-1", response)

        # asset that deleting the deployment fails if stage exists
        with pytest.raises(ClientError) as ctx:
            client.delete_deployment(restApiId=api_id, deploymentId=deployment_id_2)
        snapshot.match("delete-deployment-2-error", ctx.value.response)


class TestProxyRouting:
    @markers.aws.validated
    def test_proxy_routing_with_hardcoded_resource_sibling(
        self,
        aws_client,
        create_rest_apigw,
        apigw_redeploy_api,
    ):
        api_id, _, root_id = create_rest_apigw(name="test proxy routing")

        def _create_mock_integration_with_200_response_template(
            resource_id: str, http_method: str, response_template: dict
        ):
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                authorizationType="NONE",
            )

            aws_client.apigateway.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
            )

            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                type="MOCK",
                requestTemplates={"application/json": '{"statusCode": 200}'},
            )

            aws_client.apigateway.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
                selectionPattern="",
                responseTemplates={"application/json": json.dumps(response_template)},
            )

        resource = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )
        hardcoded_resource_id = resource["id"]

        response_template_post = {"statusCode": 200, "message": "POST request"}
        _create_mock_integration_with_200_response_template(
            hardcoded_resource_id, "POST", response_template_post
        )

        resource = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=hardcoded_resource_id, pathPart="any"
        )
        any_resource_id = resource["id"]

        response_template_any = {"statusCode": 200, "message": "ANY request"}
        _create_mock_integration_with_200_response_template(
            any_resource_id, "ANY", response_template_any
        )

        resource = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="{proxy+}"
        )
        proxy_resource_id = resource["id"]
        response_template_options = {"statusCode": 200, "message": "OPTIONS request"}
        _create_mock_integration_with_200_response_template(
            proxy_resource_id, "OPTIONS", response_template_options
        )

        stage_name = "dev"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

        url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")

        def _invoke_api(req_url: str, http_method: str, expected_type: str):
            _response = requests.request(http_method.upper(), req_url)
            assert _response.ok
            assert _response.json()["message"] == f"{expected_type} request"

        retries = 10 if is_aws_cloud() else 3
        sleep = 3 if is_aws_cloud() else 1
        retry(
            _invoke_api,
            retries=retries,
            sleep=sleep,
            req_url=url,
            http_method="OPTIONS",
            expected_type="OPTIONS",
        )
        retry(
            _invoke_api,
            retries=retries,
            sleep=sleep,
            req_url=url,
            http_method="POST",
            expected_type="POST",
        )
        any_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test/any")
        retry(
            _invoke_api,
            retries=retries,
            sleep=sleep,
            req_url=any_url,
            http_method="OPTIONS",
            expected_type="ANY",
        )
        retry(
            _invoke_api,
            retries=retries,
            sleep=sleep,
            req_url=any_url,
            http_method="GET",
            expected_type="ANY",
        )
