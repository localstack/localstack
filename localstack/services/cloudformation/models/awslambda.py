import json
import os
import random
import string

from localstack.services.awslambda.lambda_utils import get_handler_file_from_name
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    select_parameters,
)
from localstack.services.cloudformation.packages import cloudformation_package
from localstack.services.cloudformation.service_models import LOG, REF_ID_ATTRS, GenericBaseModel
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import (
    cp_r,
    is_base64,
    is_zip_file,
    mkdir,
    new_tmp_dir,
    rm_rf,
    save_file,
    select_attributes,
    to_bytes,
)
from localstack.utils.strings import short_uid
from localstack.utils.testutil import create_zip_file


class LambdaFunction(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Function"

    def fetch_state(self, stack_name, resources):
        func_name = self.resolve_refs_recursively(stack_name, self.props["FunctionName"], resources)
        return aws_stack.connect_to_service("lambda").get_function(FunctionName=func_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        func_name = self.props.get("FunctionName")
        if attribute == "Arn":
            return arns.lambda_function_arn(func_name)
        return func_name

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = aws_stack.connect_to_service("lambda")
        config_keys = [
            "Description",
            "Environment",
            "FunctionName",
            "Handler",
            "ImageConfig",
            "Layers",
            "MemorySize",
            "Role",
            "Runtime",
            "Timeout",
            "TracingConfig",
            "VpcConfig",
        ]
        update_config_props = select_attributes(props, config_keys)
        update_config_props = self.resolve_refs_recursively(
            stack_name, update_config_props, resources
        )
        if "Timeout" in update_config_props:
            update_config_props["Timeout"] = int(update_config_props["Timeout"])
        if "Code" in props:
            code = props["Code"] or {}
            if not code.get("ZipFile"):
                LOG.debug(
                    'Updating code for Lambda "%s" from location: %s', props["FunctionName"], code
                )
            code = LambdaFunction.get_lambda_code_param(props, _include_arch=True)
            client.update_function_code(FunctionName=props["FunctionName"], **code)
        if "Environment" in update_config_props:
            environment_variables = update_config_props["Environment"].get("Variables", {})
            update_config_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }
        return client.update_function_configuration(**update_config_props)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        func_name = resource.get("Properties", {}).get("FunctionName")
        if not func_name:
            resource["Properties"]["FunctionName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_lambda_code_param(params, _include_arch=False, **kwargs):
        code = params.get("Code", {})
        zip_file = code.get("ZipFile")
        if zip_file and not is_base64(zip_file) and not is_zip_file(to_bytes(zip_file)):
            tmp_dir = new_tmp_dir()
            handler_file = get_handler_file_from_name(params["Handler"], runtime=params["Runtime"])
            tmp_file = os.path.join(tmp_dir, handler_file)
            save_file(tmp_file, zip_file)

            # add 'cfn-response' module to archive - see:
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
            cloudformation_installer = cloudformation_package.get_installer()
            cloudformation_installer.install()
            cfn_response_tmp_file = cloudformation_installer.get_executable_path()

            cfn_response_mod_dir = os.path.join(tmp_dir, "node_modules", "cfn-response")
            mkdir(cfn_response_mod_dir)
            cp_r(
                cfn_response_tmp_file,
                os.path.join(cfn_response_mod_dir, "index.js"),
            )

            # create zip file
            zip_file = create_zip_file(tmp_dir, get_content=True)
            code["ZipFile"] = zip_file
            rm_rf(tmp_dir)
        if _include_arch and "Architectures" in params:
            code["Architectures"] = params.get("Architectures")
        return code

    @staticmethod
    def get_deploy_templates():
        def get_delete_params(params, **kwargs):
            return {"FunctionName": params.get("FunctionName")}

        def get_environment_params(params, **kwargs):
            # botocore/data/lambda/2015-03-31/service-2.json:1161 (EnvironmentVariableValue)
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-environment.html
            if "Environment" in params:
                environment_variables = params["Environment"].get("Variables", {})
                return {"Variables": {k: str(v) for k, v in environment_variables.items()}}

        def result_handler(result, resource_id, resources, resource_type):
            """waits for the lambda to be in a "terminal" state, i.e. not pending"""
            lambda_client = aws_stack.connect_to_service("lambda")
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=result["FunctionArn"])

        return {
            "create": {
                "function": "create_function",
                "parameters": {
                    "Architectures": "Architectures",
                    "Code": LambdaFunction.get_lambda_code_param,
                    "Description": "Description",
                    "Environment": get_environment_params,
                    "FunctionName": "FunctionName",
                    "Handler": "Handler",
                    "ImageConfig": "ImageConfig",
                    "PackageType": "PackageType",
                    "Layers": "Layers",
                    "MemorySize": "MemorySize",
                    "Runtime": "Runtime",
                    "Role": "Role",
                    "Timeout": "Timeout",
                    "TracingConfig": "TracingConfig",
                    "VpcConfig": "VpcConfig"
                    # TODO add missing fields
                },
                "defaults": {"Role": "test_role"},
                "types": {"Timeout": int, "MemorySize": int},
                "result_handler": result_handler,
            },
            "delete": {"function": "delete_function", "parameters": get_delete_params},
        }


class LambdaFunctionVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Version"

    def fetch_state(self, stack_name, resources):

        props = self.props
        if not self.physical_resource_id:
            return None

        function_name = props["FunctionName"]
        qualifier = self.resource_json["Version"]

        lambda_client = aws_stack.connect_to_service("lambda")
        return lambda_client.get_function(FunctionName=function_name, Qualifier=qualifier)

    @staticmethod
    def get_deploy_templates():
        def _store_version(result, resource_id, resources, resource_type):
            resources[resource_id]["Version"] = result["Version"]
            resources[resource_id]["PhysicalResourceId"] = result["FunctionArn"]

        return {
            "create": {
                "function": "publish_version",
                "parameters": select_parameters("FunctionName", "CodeSha256", "Description"),
                "result_handler": _store_version,
            }
        }


class LambdaEventSourceMapping(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventSourceMapping"

    def fetch_state(self, stack_name, resources):
        props = self.props
        source_arn = props.get("EventSourceArn")
        self_managed_src = props.get("SelfManagedEventSource")
        function_name = self.resolve_refs_recursively(stack_name, props["FunctionName"], resources)
        source_arn = self.resolve_refs_recursively(stack_name, source_arn, resources)
        if not function_name or (not source_arn and not self_managed_src):
            raise Exception("ResourceNotFound")

        def _matches(m):
            return m["FunctionArn"] == lambda_arn and (
                m.get("EventSourceArn") == source_arn
                or m.get("SelfManagedEventSource") == self_managed_src
            )

        client = aws_stack.connect_to_service("lambda")
        lambda_arn = client.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]
        kwargs = {"EventSourceArn": source_arn} if source_arn else {}
        mappings = client.list_event_source_mappings(FunctionName=function_name, **kwargs)
        mapping = list(filter(lambda m: _matches(m), mappings["EventSourceMappings"]))
        if not mapping:
            raise Exception("ResourceNotFound")
        return mapping[0]

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in REF_ID_ATTRS:
            return self.props.get("UUID")
        return super(LambdaEventSourceMapping, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("UUID")

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {"function": "create_event_source_mapping"},
            "delete": {"function": "delete_event_source_mapping", "parameters": ["UUID"]},
        }


class LambdaPermission(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Permission"

    def fetch_state(self, stack_name, resources):
        props = self.props
        func_name = self.resolve_refs_recursively(stack_name, props.get("FunctionName"), resources)
        lambda_client = aws_stack.connect_to_service("lambda")
        return lambda_client.get_policy(FunctionName=func_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        # return statement ID here to indicate that the resource has been deployed
        return self.props.get("Sid")

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        parameters_to_select = ["FunctionName", "Action", "Principal", "SourceArn"]
        update_config_props = select_attributes(props, parameters_to_select)
        update_config_props = self.resolve_refs_recursively(
            stack_name, update_config_props, resources
        )

        client = aws_stack.connect_to_service("lambda")
        sid = new_resource["PhysicalResourceId"]

        client.remove_permission(FunctionName=update_config_props["FunctionName"], StatementId=sid)

        return client.add_permission(StatementId=sid, **update_config_props)

    @staticmethod
    def get_deploy_templates():
        def _store_physical_id(result, resource_id, resources, resource_type):
            parsed_statement = json.loads(result["Statement"])
            resources[resource_id]["PhysicalResourceId"] = parsed_statement["Sid"]

        def lambda_permission_params(params, resources, resource_id, **kwargs):
            result = select_parameters("FunctionName", "Action", "Principal", "SourceArn")(
                params, **kwargs
            )
            # generate SID
            # e.g. stack-78d0ac66-fnAllowInvokeLambdaPermissionsStacktopicF723B1A748672DB5-1D7VMEAZ2UQIN
            # e.g. stack-6283277e-fnAllowInvokeLambdaPermissionsStacktopicF48672DB5-19EAQW5GIWOS5 when the functional ID is shorter
            suffix = "".join(random.choices(string.digits + string.ascii_uppercase, k=13))
            prefix = kwargs.get("stack_name")
            if prefix:
                result["StatementId"] = f"{prefix}-{resource_id}-{suffix}"
            else:
                result["StatementId"] = f"{resource_id}-{suffix}"
            return result

        def get_delete_params(params, **kwargs):
            resources = kwargs["resources"]
            resource_id = kwargs["resource_id"]
            statement_id = resources[resource_id]["PhysicalResourceId"]
            return {"FunctionName": params.get("FunctionName"), "StatementId": statement_id}

        return {
            "create": {
                "function": "add_permission",
                "parameters": lambda_permission_params,
                "result_handler": _store_physical_id,
            },
            "delete": {"function": "remove_permission", "parameters": get_delete_params},
        }


class LambdaEventInvokeConfig(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventInvokeConfig"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("lambda")
        props = self.props
        result = client.get_function_event_invoke_config(
            FunctionName=props.get("FunctionName"),
            Qualifier=props.get("FunctionName", "$LATEST"),
        )
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        props = self.props
        return "lambdaconfig-%s-%s" % (
            props.get("FunctionName"),
            props.get("Qualifier"),
        )

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {"function": "put_function_event_invoke_config"},
            "delete": {
                "function": "delete_function_event_invoke_config",
                "parameters": {
                    "FunctionName": "FunctionName",
                    "Qualifier": "Qualifier",
                },
            },
        }


class LambdaUrl(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::Lambda::Url"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get(
            "TargetFunctionArn"
        )  # TODO: if this isn't an ARN we need to resolve the full ARN here

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("lambda")

        kwargs = {"FunctionName": self.props.get("TargetFunctionArn")}
        qualifier = self.props.get("Qualifier")
        if qualifier:
            kwargs["Qualifier"] = qualifier

        return client.get_function_url_config(**kwargs)

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "FunctionArn":
            return self.props.get("TargetFunctionArn")
        if attribute_name == "FunctionUrl":
            client = aws_stack.connect_to_service("lambda")
            url_config = client.get_function_url_config(
                FunctionName=self.props.get("TargetFunctionArn"),
                Qualifier=self.props.get("Qualifier", "$LATEST"),
            )
            return url_config["FunctionUrl"]
        return super(LambdaUrl, self).get_cfn_attribute(attribute_name)

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_function_url_config",
                "parameters": {
                    "Qualifier": "Qualifier",
                    "Cors": "Cors",
                    "FunctionName": "TargetFunctionArn",
                    "AuthType": "AuthType",
                },
            },
            "delete": {
                "function": "delete_function_url_config",
                "parameters": {"FunctionName": "TargetFunctionArn", "Qualifier": "Qualifier"},
            },
        }


class LambdaAlias(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Alias"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("lambda")
        props = self.props
        result = client.get_alias(FunctionName=props.get("FunctionName"), Name=props.get("Name"))
        return result

    @staticmethod
    def get_deploy_templates():
        def _store_arn(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["AliasArn"]

        return {
            "create": {"function": "create_alias", "result_handler": _store_arn},
            "delete": {
                "function": "delete_alias",
                "parameters": {
                    "FunctionName": "FunctionName",
                    "Name": "Name",
                },
            },
        }


class LambdaCodeSigningConfig(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::CodeSigningConfig"

    def fetch_state(self, stack_name, resources):
        if not self.physical_resource_id:
            return None

        client = aws_stack.connect_to_service("lambda")
        result = client.get_code_signing_config(CodeSigningConfigArn=self.physical_resource_id)[
            "CodeSigningConfig"
        ]
        return result

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.physical_resource_id

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "CodeSigningConfigId":
            return self.props()["CodeSigningConfigId"]

        return self.physical_resource_id

    @classmethod
    def get_deploy_templates(cls):
        def _store_arn(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["CodeSigningConfig"][
                "CodeSigningConfigArn"
            ]

        def _arn(params, resources, resource_id, **kwargs):
            resource = cls(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        return {
            "create": {"function": "create_code_signing_config", "result_handler": _store_arn},
            "delete": {
                "function": "delete_code_signing_config",
                "parameters": {
                    "CodeSigningConfigArn": _arn,
                },
            },
        }


# TODO: test
class LambdaLayerVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::LayerVersion"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.state.get("LayerVersionArn")

    def fetch_state(self, stack_name, resources):
        layer_name = self.resolve_refs_recursively(
            stack_name, self.props.get("LayerName"), resources
        )
        # TODO extract region name if layer_name is an ARN
        client = aws_stack.connect_to_service("lambda")
        layers = client.list_layer_versions(LayerName=layer_name).get("LayerVersions", [])
        return layers[-1] if layers else None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        resource["Properties"]["LayerName"] = (
            resource["Properties"].get("LayerName") or f"layer-{short_uid()}"
        )

    @staticmethod
    def get_deploy_templates():
        return {"create": {"function": "publish_layer_version"}}


# TODO: test
# TODO: remove inheritance
class LambdaLayerVersionPermission(LambdaPermission):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::LayerVersionPermission"

    def fetch_state(self, stack_name, resources):
        props = self.props
        props["LayerVersionArn"] = self.resolve_refs_recursively(
            stack_name, props["LayerVersionArn"], resources
        )
        layer_name, version_number = self.layer_name_and_version(props)
        layer_arn = arns.lambda_layer_arn(layer_name)
        layer_arn_qualified = "%s:%s" % (layer_arn, version_number)
        result = self.do_fetch_state(layer_name, layer_arn_qualified)
        return result

    @staticmethod
    def layer_name_and_version(params):
        layer_arn = params.get("LayerVersionArn", "")
        parts = layer_arn.split(":")
        layer_name = parts[6] if ":" in layer_arn else layer_arn
        version_number = int(parts[7] if len(parts) > 7 else 1)  # TODO fetch latest version number
        return layer_name, version_number

    @classmethod
    def get_deploy_templates(cls):
        def layer_permission_params(params, **kwargs):
            layer_name, version_number = cls.layer_name_and_version(params)
            result = select_attributes(params, ["Action", "Principal"])
            result["StatementId"] = short_uid()
            result["LayerName"] = layer_name
            result["VersionNumber"] = version_number
            return result

        return {
            "create": {
                "function": "add_layer_version_permission",
                "parameters": layer_permission_params,
            }
        }
