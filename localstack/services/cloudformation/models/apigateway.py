from urllib.parse import urlparse

from localstack.services.cloudformation.deployment_utils import (
    lambda_keys_to_lower,
    params_list_to_dict,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import keys_to_lower, select_attributes


class GatewayResponse(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::GatewayResponse"

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        if not api_id:
            return
        client = aws_stack.connect_to_service("apigateway")
        result = client.get_gateway_response(restApiId=api_id, responseType=props["ResponseType"])
        return result if "responseType" in result else None


class GatewayRequestValidator(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::RequestValidator"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        props = self.props
        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        name = self.resolve_refs_recursively(stack_name, props["Name"], resources)
        result = client.get_request_validators(restApiId=api_id).get("items", [])
        result = [r for r in result if r.get("name") == name]
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_request_validator",
                "parameters": {
                    "name": "Name",
                    "restApiId": "RestApiId",
                    "validateRequestBody": "ValidateRequestBody",
                    "validateRequestParameters": "ValidateRequestParameters",
                },
            },
            "delete": {
                "function": "delete_request_validator",
                "parameters": {"restApiId": "RestApiId", "requestValidatorId": "id"},
            },
        }


class GatewayRestAPI(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::RestApi"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        apis = aws_stack.connect_to_service("apigateway").get_rest_apis()["items"]
        api_name = self.props.get("Name") or self.resource_id
        api_name = self.resolve_refs_recursively(stack_name, api_name, resources)
        result = list(filter(lambda api: api["name"] == api_name, apis))
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def _api_id(params, resources, resource_id, **kwargs):
            resource = GatewayRestAPI(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        return {
            "create": {
                "function": "create_rest_api",
                "parameters": {"name": "Name", "description": "Description"},
            },
            "delete": {
                "function": "delete_rest_api",
                "parameters": {
                    "restApiId": _api_id,
                },
            },
        }


class GatewayDeployment(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Deployment"

    def fetch_state(self, stack_name, resources):
        api_id = self.props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)

        if not api_id:
            return None

        result = aws_stack.connect_to_service("apigateway").get_deployments(restApiId=api_id)[
            "items"
        ]
        # TODO possibly filter results by stage name or other criteria

        return result[0] if result else None


class GatewayResource(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Resource"

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        parent_id = self.resolve_refs_recursively(stack_name, props.get("ParentId"), resources)

        if not api_id or not parent_id:
            return None

        api_resources = aws_stack.connect_to_service("apigateway").get_resources(restApiId=api_id)[
            "items"
        ]
        target_resource = list(
            filter(
                lambda res: res.get("parentId") == parent_id
                and res["pathPart"] == props["PathPart"],
                api_resources,
            )
        )

        if not target_resource:
            return None

        path = aws_stack.get_apigateway_path_for_resource(
            api_id, target_resource[0]["id"], resources=api_resources
        )
        result = list(filter(lambda res: res["path"] == path, api_resources))
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def get_apigw_resource_params(params, **kwargs):
            result = {
                "restApiId": params.get("RestApiId"),
                "pathPart": params.get("PathPart"),
                "parentId": params.get("ParentId"),
            }
            if not result.get("parentId"):
                # get root resource id
                apigw = aws_stack.connect_to_service("apigateway")
                resources = apigw.get_resources(restApiId=result["restApiId"])["items"]
                root_resource = ([r for r in resources if r["path"] == "/"] or [None])[0]
                if not root_resource:
                    raise Exception(
                        "Unable to find root resource for REST API %s" % result["restApiId"]
                    )
                result["parentId"] = root_resource["id"]
            return result

        return {
            "create": {
                "function": "create_resource",
                "parameters": get_apigw_resource_params,
            }
        }


class GatewayMethod(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Method"

    def fetch_state(self, stack_name, resources):
        props = self.props

        api_id = self.resolve_refs_recursively(stack_name, props["RestApiId"], resources)
        res_id = self.resolve_refs_recursively(stack_name, props["ResourceId"], resources)
        if not api_id or not res_id:
            return None

        res_obj = aws_stack.connect_to_service("apigateway").get_resource(
            restApiId=api_id, resourceId=res_id
        )
        match = [
            v
            for (k, v) in res_obj.get("resourceMethods", {}).items()
            if props["HttpMethod"] in (v.get("httpMethod"), k)
        ]

        int_props = props.get("Integration") or {}
        if int_props.get("Type") == "AWS_PROXY":
            match = [
                m
                for m in match
                if m.get("methodIntegration", {}).get("type") == "AWS_PROXY"
                and m.get("methodIntegration", {}).get("httpMethod")
                == int_props.get("IntegrationHttpMethod")
            ]

        return match[0] if match else None

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("apigateway")
        integration = props.get("Integration")
        kwargs = {
            "restApiId": props["RestApiId"],
            "resourceId": props["ResourceId"],
            "httpMethod": props["HttpMethod"],
            "requestParameters": props.get("RequestParameters") or {},
        }
        if integration:
            kwargs["type"] = integration["Type"]
            if integration.get("IntegrationHttpMethod"):
                kwargs["integrationHttpMethod"] = integration.get("IntegrationHttpMethod")
            if integration.get("Uri"):
                kwargs["uri"] = integration.get("Uri")
            kwargs["requestParameters"] = integration.get("RequestParameters") or {}
            return client.put_integration(**kwargs)
        kwargs["authorizationType"] = props.get("AuthorizationType")

        return client.put_method(**kwargs)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        result = "%s-%s-%s" % (
            props.get("RestApiId"),
            props.get("ResourceId"),
            props.get("HttpMethod"),
        )
        return result

    @classmethod
    def get_deploy_templates(cls):
        """
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-method.html
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apitgateway-method-methodresponse.html
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apitgateway-method-integration.html
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apitgateway-method-integration-integrationresponse.html
        """

        def _subresources(resource_id, resources, resource_type, func, stack_name):
            apigateway = aws_stack.connect_to_service("apigateway")
            resource = cls(resources[resource_id])
            props = resource.props

            integration = props.get("Integration")
            if integration:
                api_id = resource.resolve_refs_recursively(
                    stack_name, props["RestApiId"], resources
                )
                res_id = resource.resolve_refs_recursively(
                    stack_name, props["ResourceId"], resources
                )
                kwargs = {}
                if integration.get("Uri"):
                    uri = resource.resolve_refs_recursively(
                        stack_name, integration.get("Uri"), resources
                    )

                    # Moto has a validate method on Uri for integration_type "HTTP" | "HTTP_PROXY" that does not accept
                    # Uri value without path, we need to add path ("/") if not exists
                    if integration.get("Type") in ["HTTP", "HTTP_PROXY"]:
                        rs = urlparse(uri)
                        if not rs.path:
                            uri = "{}/".format(uri)

                    kwargs["uri"] = uri

                if integration.get("IntegrationHttpMethod"):
                    kwargs["integrationHttpMethod"] = integration["IntegrationHttpMethod"]

                if integration.get("RequestTemplates"):
                    kwargs["requestTemplates"] = integration["RequestTemplates"]

                if integration.get("Credentials"):
                    kwargs["credentials"] = integration["Credentials"]

                if integration.get("RequestParameters"):
                    kwargs["requestParameters"] = integration["RequestParameters"]

                apigateway.put_integration(
                    restApiId=api_id,
                    resourceId=res_id,
                    httpMethod=props["HttpMethod"],
                    type=integration["Type"],
                    **kwargs,
                )

            responses = props.get("MethodResponses") or []
            for response in responses:
                api_id = resource.resolve_refs_recursively(
                    stack_name, props["RestApiId"], resources
                )
                res_id = resource.resolve_refs_recursively(
                    stack_name, props["ResourceId"], resources
                )
                apigateway.put_method_response(
                    restApiId=api_id,
                    resourceId=res_id,
                    httpMethod=props["HttpMethod"],
                    statusCode=str(response["StatusCode"]),
                    responseParameters=response.get("ResponseParameters", {}),
                )

        return {
            "create": [
                {
                    "function": "put_method",
                    "parameters": {
                        "restApiId": "RestApiId",
                        "resourceId": "ResourceId",
                        "httpMethod": "HttpMethod",
                        "authorizationType": "AuthorizationType",
                        "authorizerId": "AuthorizerId",
                        "requestParameters": "RequestParameters",
                    },
                },
                {
                    "function": _subresources  # dynamic mapping for additional sdk calls for this CFn resource
                },
            ]
        }


class GatewayStage(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Stage"

    def fetch_state(self, stack_name, resources):
        api_id = self.props.get("RestApiId") or self.resource_id
        api_id = self.resolve_refs_recursively(stack_name, api_id, resources)
        if not api_id:
            return None
        result = aws_stack.connect_to_service("apigateway").get_stage(
            restApiId=api_id, stageName=self.props["StageName"]
        )
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    @staticmethod
    def get_deploy_templates():
        def get_params(params, **kwargs):
            result = keys_to_lower(params)
            param_names = [
                "restApiId",
                "stageName",
                "deploymentId",
                "description",
                "cacheClusterEnabled",
                "cacheClusterSize",
                "variables",
                "documentationVersion",
                "canarySettings",
                "tracingEnabled",
                "tags",
            ]
            result = select_attributes(result, param_names)
            result["tags"] = {t["key"]: t["value"] for t in result.get("tags", [])}
            return result

        return {"create": {"function": "create_stage", "parameters": get_params}}


class GatewayUsagePlan(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::UsagePlan"

    def fetch_state(self, stack_name, resources):
        plan_name = self.props.get("UsagePlanName")
        plan_name = self.resolve_refs_recursively(stack_name, plan_name, resources)
        result = aws_stack.connect_to_service("apigateway").get_usage_plans().get("items", [])
        result = [r for r in result if r["name"] == plan_name]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_usage_plan",
                "parameters": {
                    "name": "UsagePlanName",
                    "description": "Description",
                    "apiStages": lambda_keys_to_lower("ApiStages"),
                    "quota": lambda_keys_to_lower("Quota"),
                    "throttle": lambda_keys_to_lower("Throttle"),
                    "tags": params_list_to_dict("Tags"),
                },
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayApiKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::ApiKey"

    def fetch_state(self, stack_name, resources):
        props = self.props
        key_name = self.resolve_refs_recursively(stack_name, props.get("Name"), resources)
        cust_id = props.get("CustomerId")
        result = aws_stack.connect_to_service("apigateway").get_api_keys().get("items", [])
        result = [
            r
            for r in result
            if r.get("name") == key_name and cust_id in (None, r.get("customerId"))
        ]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_api_key",
                "parameters": {
                    "description": "Description",
                    "customerId": "CustomerId",
                    "name": "Name",
                    "value": "Value",
                    "enabled": "Enabled",
                    "stageKeys": lambda_keys_to_lower("StageKeys"),
                    "tags": params_list_to_dict("Tags"),
                },
                "types": {"enabled": bool},
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayUsagePlanKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::UsagePlanKey"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        key_id = self.resolve_refs_recursively(stack_name, self.props.get("KeyId"), resources)
        key_type = self.resolve_refs_recursively(stack_name, self.props.get("KeyType"), resources)
        plan_id = self.resolve_refs_recursively(
            stack_name, self.props.get("UsagePlanId"), resources
        )
        result = client.get_usage_plan_keys(usagePlanId=plan_id).get("items", [])
        result = [r for r in result if r["id"] == key_id and key_type in [None, r.get("type")]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_usage_plan_key",
                "parameters": lambda_keys_to_lower(),
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")


class GatewayModel(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Model"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        api_id = self.resolve_refs_recursively(stack_name, self.props["RestApiId"], resources)

        items = client.get_models(restApiId=api_id)["items"]
        if not items:
            return None

        model_name = self.resolve_refs_recursively(stack_name, self.props["Name"], resources)
        models = [item for item in items if item["name"] == model_name]
        if models:
            return models[0]

        return None


class GatewayAccount(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Account"
