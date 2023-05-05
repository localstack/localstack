import json
from urllib.parse import urlparse

from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    lambda_keys_to_lower,
    params_list_to_dict,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack, queries
from localstack.utils.common import keys_to_lower, select_attributes, to_bytes
from localstack.utils.strings import first_char_to_lower


class GatewayResponse(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::GatewayResponse"

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = props.get("RestApiId")
        if not api_id:
            return
        client = aws_stack.connect_to_service("apigateway")
        result = client.get_gateway_response(restApiId=api_id, responseType=props["ResponseType"])
        return result if "responseType" in result else None

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_gateway_response",
                "parameters": {
                    "restApiId": "RestApiId",
                    "responseType": "ResponseType",
                    "statusCode": "StatusCode",
                    "responseParameters": "ResponseParameters",
                    "responseTemplates": "ResponseTemplates",
                },
            }
        }


class GatewayRequestValidator(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::RequestValidator"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        props = self.props
        api_id = props["RestApiId"]
        name = props["Name"]
        result = client.get_request_validators(restApiId=api_id).get("items", [])
        result = [r for r in result if r.get("name") == name]
        return result[0] if result else None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource["Properties"].get("Name")
        if not role_name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

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

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "RootResourceId":
            api_id = self.props.get("id")
            resources = aws_stack.connect_to_service("apigateway").get_resources(restApiId=api_id)[
                "items"
            ]
            for res in resources:
                if res["path"] == "/" and not res.get("parentId"):
                    return res["id"]
        return super(GatewayRestAPI, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        if not self.props.get("id"):
            return None

        return aws_stack.connect_to_service("apigateway").get_rest_api(
            restApiId=self.props.get("id")
        )

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("Name")
        if not role_name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _api_id(params, resources, resource_id, **kwargs):
            resource = cls(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        def _create(resource_id, resources, resource_type, func, stack_name):
            client = aws_stack.connect_to_service("apigateway")
            resource = resources[resource_id]
            props = resource["Properties"]

            kwargs = select_attributes(
                props,
                [
                    "Name",
                    "Description",
                    "Version",
                    "CloneFrom",
                    "BinaryMediaTypes",
                    "MinimumCompressionSize",
                    "ApiKeySource",
                    "EndpointConfiguration",
                    "Policy",
                    "Tags",
                    "DisableExecuteApiEndpoint",
                ],
            )
            kwargs = keys_to_lower(kwargs, skip_children_of=["policy"])
            kwargs["tags"] = {tag["key"]: tag["value"] for tag in kwargs.get("tags", [])}

            cfn_client = aws_stack.connect_to_service("cloudformation")
            stack_id = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
            kwargs["tags"].update(
                {
                    "aws:cloudformation:logical-id": resource_id,
                    "aws:cloudformation:stack-name": stack_name,
                    "aws:cloudformation:stack-id": stack_id,
                }
            )
            if isinstance(kwargs.get("policy"), dict):
                kwargs["policy"] = json.dumps(kwargs["policy"])

            result = client.create_rest_api(**kwargs)

            body = props.get("Body")
            if body:
                # the default behavior for imports via CFn is basepath=ignore (validated against AWS)
                api_params = {"basepath": "ignore"}
                body = json.dumps(body) if isinstance(body, dict) else body
                client.put_rest_api(
                    restApiId=result["id"], body=to_bytes(body), parameters=api_params
                )

            props["id"] = result["id"]
            return result

        return {
            "create": {"function": _create},
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
        api_id = self.props.get("RestApiId")

        if not api_id:
            return None

        client = aws_stack.connect_to_service("apigateway")
        result = client.get_deployments(restApiId=api_id)["items"]
        # TODO possibly filter results by stage name or other criteria

        return result[0] if result else None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_deployment",
                "parameters": {
                    "restApiId": "RestApiId",
                    "stageName": "StageName",
                    "stageDescription": "StageDescription",
                    "description": "Description",
                },
            }
        }


class GatewayResource(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Resource"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def fetch_state(self, stack_name, resources):
        props = self.props
        api_id = props.get("RestApiId") or self.logical_resource_id
        parent_id = props.get("ParentId")

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

        path = queries.get_apigateway_path_for_resource(
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

        api_id = props["RestApiId"]
        res_id = props["ResourceId"]
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
            kwargs["requestTemplates"] = integration.get("RequestTemplates") or {}
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
                api_id = props["RestApiId"]
                res_id = props["ResourceId"]

                kwargs = keys_to_lower(integration)
                if integration.get("Uri"):
                    uri = integration.get("Uri")

                    # Moto has a validate method on Uri for integration_type "HTTP" | "HTTP_PROXY" that does not accept
                    # Uri value without path, we need to add path ("/") if not exists
                    if integration.get("Type") in ["HTTP", "HTTP_PROXY"]:
                        rs = urlparse(uri)
                        if not rs.path:
                            uri = "{}/".format(uri)

                    kwargs["uri"] = uri

                integration_responses = kwargs.pop("integrationResponses", [])
                method = props.get("HttpMethod")

                apigateway.put_integration(
                    restApiId=api_id,
                    resourceId=res_id,
                    httpMethod=method,
                    **kwargs,
                )

                for integration_response in integration_responses:
                    integration_response["statusCode"] = str(integration_response["statusCode"])
                    integration_response["responseParameters"] = integration_response.get(
                        "responseParameters", {}
                    )
                    apigateway.put_integration_response(
                        restApiId=api_id,
                        resourceId=res_id,
                        httpMethod=method,
                        **keys_to_lower(integration_response),
                    )

            responses = props.get("MethodResponses") or []
            for response in responses:
                api_id = props["RestApiId"]
                res_id = props["ResourceId"]
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
                        "apiKeyRequired": "ApiKeyRequired",
                        "authorizationType": "AuthorizationType",
                        "authorizerId": "AuthorizerId",
                        "requestParameters": "RequestParameters",
                        "requestModels": "RequestModels",
                        "requestValidatorId": "RequestValidatorId",
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
        api_id = self.props.get("RestApiId") or self.logical_resource_id
        if not api_id:
            return None
        result = aws_stack.connect_to_service("apigateway").get_stage(
            restApiId=api_id, stageName=self.props["StageName"]
        )
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("StageName")

    @staticmethod
    def get_deploy_templates():
        def get_params(resource_props, stack_name, resources, resource_id):
            stage_name = resource_props.get("StageName", "default")
            resources[resource_id]["Properties"]["StageName"] = stage_name
            result = keys_to_lower(resource_props)
            param_names = [
                "restApiId",
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
            result["stageName"] = stage_name
            return result

        return {
            "create": {
                "function": "create_stage",
                "parameters": get_params,
            }
        }


class GatewayUsagePlan(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::UsagePlan"

    def fetch_state(self, stack_name, resources):
        plan_name = self.props.get("UsagePlanName")
        result = aws_stack.connect_to_service("apigateway").get_usage_plans().get("items", [])
        result = [r for r in result if r["name"] == plan_name]
        return (result or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("UsagePlanName")
        if not role_name:
            resource["Properties"]["UsagePlanName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

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
                "types": {
                    "limit": int,
                    "burstLimit": int,
                    "rateLimit": float,
                },
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("id")

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        parameters_to_select = [
            "UsagePlanName",
            "Description",
            "ApiStages",
            "Quota",
            "Throttle",
            "Tags",
        ]
        update_config_props = select_attributes(props, parameters_to_select)

        if "Tags" in update_config_props:
            tags_dict = {}
            for tag in update_config_props:
                tags_dict.update({tag["Key"]: tag["Value"]})
            update_config_props["Tags"] = tags_dict

        usage_plan_id = new_resource["PhysicalResourceId"]

        patch_operations = []

        for parameter in update_config_props:
            value = update_config_props[parameter]
            if parameter == "ApiStages":
                patch_operations.append(
                    {
                        "op": "remove",
                        "path": f"/{first_char_to_lower(parameter)}",
                    }
                )

                for stage in value:
                    patch_operations.append(
                        {
                            "op": "replace",
                            "path": f"/{first_char_to_lower(parameter)}",
                            "value": f'{stage["ApiId"]}:{stage["Stage"]}',
                        }
                    )

                    if "Throttle" in stage:
                        patch_operations.append(
                            {
                                "op": "replace",
                                "path": f'/{first_char_to_lower(parameter)}/{stage["ApiId"]}:{stage["Stage"]}',
                                "value": json.dumps(stage["Throttle"]),
                            }
                        )

            elif isinstance(value, dict):
                for item in value:
                    last_value = value[item]
                    path = f"/{first_char_to_lower(parameter)}/{first_char_to_lower(item)}"
                    patch_operations.append({"op": "replace", "path": path, "value": last_value})
            else:
                patch_operations.append(
                    {"op": "replace", "path": f"/{first_char_to_lower(parameter)}", "value": value}
                )
        client = aws_stack.connect_to_service("apigateway")
        client.update_usage_plan(usagePlanId=usage_plan_id, patchOperations=patch_operations)


class GatewayApiKey(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::ApiKey"

    def fetch_state(self, stack_name, resources):
        props = self.props
        key_name = props.get("Name")
        cust_id = props.get("CustomerId")
        result = aws_stack.connect_to_service("apigateway").get_api_keys().get("items", [])
        result = [
            r
            for r in result
            if r.get("name") == key_name and cust_id in (None, r.get("customerId"))
        ]
        return (result or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("Name")
        if not role_name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

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
        key_id = self.props.get("KeyId")
        key_type = self.props.get("KeyType")
        plan_id = self.props.get("UsagePlanId")
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


# TODO: add tests for this resource type
class GatewayDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::DomainName"

    def fetch_state(self, stack_name, resources):
        return aws_stack.connect_to_service("apigateway").get_domain_name(
            domainName=self.props["DomainName"]
        )

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_domain_name",
                "parameters": {
                    "certificateArn": lambda_keys_to_lower("CertificateArn"),
                    "domainName": lambda_keys_to_lower("DomainName"),
                    "endpointConfiguration": lambda_keys_to_lower("EndpointConfiguration"),
                    "mutualTlsAuthentication": lambda_keys_to_lower("MutualTlsAuthentication"),
                    "ownershipVerificationCertificateArn": lambda_keys_to_lower(
                        "OwnershipVerificationCertificateArn"
                    ),
                    "regionalCertificateArn": lambda_keys_to_lower("RegionalCertificateArn"),
                    "securityPolicy": lambda_keys_to_lower("SecurityPolicy"),
                    "tags": params_list_to_dict("Tags"),
                },
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("domainName")


# TODO: add tests for this resource type
class GatewayBasePathMapping(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::BasePathMapping"

    def fetch_state(self, stack_name, resources):
        resources = (
            aws_stack.connect_to_service("apigateway")
            .get_base_path_mappings(domainName=self.props.get("DomainName"))
            .get("items", [])
        )

        comparable = (
            [self.props.get("BasePath")] if self.props.get("BasePath") else [None, "", "(none)"]
        )

        return next(iter(res for res in resources if res.get("basePath") in comparable))

    @classmethod
    def get_deploy_templates(cls):
        def _create_base_path_mapping(resource_id, resources, *args, **kwargs):
            resource = cls(resources[resource_id])
            props = resource.props

            kwargs = {
                "domainName": props.get("DomainName"),
                "restApiId": props.get("RestApiId"),
                **({"basePath": props.get("BasePath")} if props.get("BasePath") else {}),
                **({"stage": props.get("Stage")} if props.get("Stage") else {}),
            }

            aws_stack.connect_to_service("apigateway").create_base_path_mapping(**kwargs)

        return {"create": {"function": _create_base_path_mapping}}

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("restApiId")


class GatewayModel(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Model"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("apigateway")
        api_id = self.props["RestApiId"]

        items = client.get_models(restApiId=api_id)["items"]
        if not items:
            return None

        model_name = self.props["Name"]
        models = [item for item in items if item["name"] == model_name]
        if models:
            return models[0]

        return None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        props = resource.get("Properties", {})
        role_name = props.get("Name")
        if not role_name:
            props["Name"] = generate_default_name(stack_name, resource["LogicalResourceId"])

        content_type = props.get("contentType")
        if not content_type:
            props["contentType"] = "application/json"

    @staticmethod
    def get_deploy_templates():
        def _store_id(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["id"]

        return {
            "create": {
                "function": "create_model",
                "parameters": {
                    "name": "Name",
                    "restApiId": "RestApiId",
                    "schema": "Schema",
                    "contentType": "ContentType",
                },
                "types": {"schema": str},
                "result_handler": _store_id,
            }
        }


class GatewayAccount(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ApiGateway::Account"

    def fetch_state(self, stack_name, resources):
        if not self.physical_resource_id:
            return None
        client = aws_stack.connect_to_service("apigateway")
        return client.get_account()

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, *args, **kwargs):
            resource = resources[resource_id]
            props = cls(resource).props

            role_arn = props["CloudWatchRoleArn"]

            aws_stack.connect_to_service("apigateway").update_account(
                patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}]
            )

            resource["PhysicalResourceId"] = generate_default_name(
                args[2], resource["LogicalResourceId"]
            )

        def _delete(*_, **__):
            # note: deletion of accounts is currently a no-op
            pass

        return {"create": {"function": _create}, "delete": {"function": _delete}}
