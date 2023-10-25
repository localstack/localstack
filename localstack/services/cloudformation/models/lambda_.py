import json
import os
import random
import string
import uuid

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    select_parameters,
)
from localstack.services.cloudformation.packages import cloudformation_package
from localstack.services.cloudformation.service_models import LOG, GenericBaseModel
from localstack.services.lambda_.legacy.lambda_utils import get_handler_file_from_name
from localstack.utils.aws import arns
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
        func_name = self.props["FunctionName"]
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).lambda_.get_function(FunctionName=func_name)

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        function_name = (
            props.get("FunctionName")
            or new_resource.get("_last_deployed_state", new_resource.get("_state_"))["FunctionName"]
        )
        config_keys = [
            "Description",
            "Environment",
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
        update_config_props["FunctionName"] = function_name
        if "Timeout" in update_config_props:
            update_config_props["Timeout"] = int(update_config_props["Timeout"])
        if "Code" in props:
            code = props["Code"] or {}
            if not code.get("ZipFile"):
                LOG.debug('Updating code for Lambda "%s" from location: %s', function_name, code)
            code = LambdaFunction.get_lambda_code_param(
                self.account_id,
                self.region_name,
                props,
                new_resource["LogicalResourceId"],
                new_resource,
                stack_name,
                _include_arch=True,
            )
            client.update_function_code(FunctionName=function_name, **code)
        if "Environment" in update_config_props:
            environment_variables = update_config_props["Environment"].get("Variables", {})
            update_config_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }
        result = client.update_function_configuration(**update_config_props)
        connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        return result

    @staticmethod
    def add_defaults(resource, stack_name: str):
        func_name = resource.get("Properties", {}).get("FunctionName")
        if not func_name:
            resource["Properties"]["FunctionName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_lambda_code_param(
        account_id: str,
        region_name: str,
        properties: dict,
        logical_resource_id: str,
        resource: dict,
        stack_name: str,
        _include_arch=False,
    ):
        code = properties.get("Code", {}).copy()
        zip_file = code.get("ZipFile")
        if zip_file and not is_base64(zip_file) and not is_zip_file(to_bytes(zip_file)):
            tmp_dir = new_tmp_dir()
            handler_file = get_handler_file_from_name(
                properties["Handler"], runtime=properties["Runtime"]
            )
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
        if _include_arch and "Architectures" in properties:
            code["Architectures"] = properties.get("Architectures")
        return code

    @staticmethod
    def get_deploy_templates():
        def get_environment_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            # botocore/data/lambda/2015-03-31/service-2.json:1161 (EnvironmentVariableValue)
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-environment.html
            if "Environment" in properties:
                environment_variables = properties["Environment"].get("Variables", {})
                return {"Variables": {k: str(v) for k, v in environment_variables.items()}}

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            """waits for the lambda to be in a "terminal" state, i.e. not pending"""
            resource["Properties"]["Arn"] = result["FunctionArn"]
            resource["PhysicalResourceId"] = resource["Properties"]["FunctionName"]
            connect_to(aws_access_key_id=account_id, region_name=region_name).lambda_.get_waiter(
                "function_active_v2"
            ).wait(FunctionName=result["FunctionArn"])

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
                "types": {"Timeout": int, "MemorySize": int},
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_function",
                "parameters": {"FunctionName": "FunctionName"},
            },
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
        qualifier = props["Version"]

        lambda_client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).lambda_
        return lambda_client.get_function(FunctionName=function_name, Qualifier=qualifier)

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Version"] = result["Version"]
            resource["PhysicalResourceId"] = result["FunctionArn"]
            connect_to().lambda_.get_waiter("published_version_active").wait(
                FunctionName=result["FunctionName"], Qualifier=result["Version"]
            )

        return {
            "create": {
                "function": "publish_version",
                "parameters": select_parameters("FunctionName", "CodeSha256", "Description"),
                "result_handler": _handle_result,
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
        function_name = props["FunctionName"]
        if not function_name or (not source_arn and not self_managed_src):
            raise Exception("ResourceNotFound")

        def _matches(m):
            return m["FunctionArn"] == lambda_arn and (
                m.get("EventSourceArn") == source_arn
                or m.get("SelfManagedEventSource") == self_managed_src
            )

        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        lambda_arn = client.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]
        kwargs = {"EventSourceArn": source_arn} if source_arn else {}
        mappings = client.list_event_source_mappings(FunctionName=function_name, **kwargs)
        mapping = list(filter(lambda m: _matches(m), mappings["EventSourceMappings"]))
        if not mapping:
            raise Exception("ResourceNotFound")
        return mapping[0]

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["UUID"]
            resource["Properties"]["Id"] = result["UUID"]

        return {
            "create": {"function": "create_event_source_mapping", "result_handler": _handle_result},
            "delete": {"function": "delete_event_source_mapping", "parameters": ["UUID"]},
        }


class LambdaPermission(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Permission"

    def fetch_state(self, stack_name, resources):
        if not self.physical_resource_id:
            return None

        props = self.props
        func_name = props.get("FunctionName")
        lambda_client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).lambda_
        policy = lambda_client.get_policy(FunctionName=func_name)
        if not policy:
            return None

        loaded_policy = json.loads(policy["Policy"])
        statements = loaded_policy.get("Statement", [])
        matched_statements = [s for s in statements if s["Sid"] == self.physical_resource_id]
        if not matched_statements:
            return None

        return statements[0]

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        parameters_to_select = ["FunctionName", "Action", "Principal", "SourceArn"]
        update_config_props = select_attributes(props, parameters_to_select)

        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        client.remove_permission(
            FunctionName=update_config_props["FunctionName"], StatementId=self.physical_resource_id
        )
        return client.add_permission(StatementId=self.physical_resource_id, **update_config_props)

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            parsed_statement = json.loads(result["Statement"])
            resource["PhysicalResourceId"] = parsed_statement["Sid"]

        def lambda_permission_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            result = select_parameters("FunctionName", "Action", "Principal", "SourceArn")(
                account_id, region_name, properties, logical_resource_id, resource, stack_name
            )
            # generate SID
            # e.g. stack-78d0ac66-fnAllowInvokeLambdaPermissionsStacktopicF723B1A748672DB5-1D7VMEAZ2UQIN
            # e.g. stack-6283277e-fnAllowInvokeLambdaPermissionsStacktopicF48672DB5-19EAQW5GIWOS5 when the functional ID is shorter
            suffix = "".join(random.choices(string.digits + string.ascii_uppercase, k=13))
            prefix = stack_name
            if prefix:
                result["StatementId"] = f"{prefix}-{logical_resource_id}-{suffix}"
            else:
                result["StatementId"] = f"{logical_resource_id}-{suffix}"
            return result

        def get_delete_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            statement_id = resource["PhysicalResourceId"]
            return {"FunctionName": properties.get("FunctionName"), "StatementId": statement_id}

        return {
            "create": {
                "function": "add_permission",
                "parameters": lambda_permission_params,
                "result_handler": _handle_result,
            },
            "delete": {"function": "remove_permission", "parameters": get_delete_params},
        }


class LambdaEventInvokeConfig(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventInvokeConfig"

    def fetch_state(self, stack_name, resources):
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        props = self.props
        result = client.get_function_event_invoke_config(
            FunctionName=props.get("FunctionName"),
            Qualifier=props.get("FunctionName", "$LATEST"),
        )
        return result

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = str(uuid.uuid4())  # TODO: not actually a UUIDv4
            # example format: 6403f864-a20b-4373-ac8f-f8d888f6bc0f

        return {
            "create": {
                "function": "put_function_event_invoke_config",
                "result_handler": _handle_result,
            },
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

    def fetch_state(self, stack_name, resources):
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_

        kwargs = {"FunctionName": self.props.get("TargetFunctionArn")}
        qualifier = self.props.get("Qualifier")
        if qualifier:
            kwargs["Qualifier"] = qualifier

        return client.get_function_url_config(**kwargs)

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["FunctionArn"]
            resource["Properties"]["FunctionArn"] = result["FunctionArn"]
            resource["Properties"]["FunctionUrl"] = result["FunctionUrl"]

        return {
            "create": {
                "function": "create_function_url_config",
                "parameters": {
                    "Qualifier": "Qualifier",
                    "Cors": "Cors",
                    "FunctionName": "TargetFunctionArn",
                    "AuthType": "AuthType",
                },
                "result_handler": _handle_result,
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
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        props = self.props
        result = client.get_alias(FunctionName=props.get("FunctionName"), Name=props.get("Name"))
        return result

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["AliasArn"]

        return {
            "create": {"function": "create_alias", "result_handler": _handle_result},
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

        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        result = client.get_code_signing_config(CodeSigningConfigArn=self.physical_resource_id)[
            "CodeSigningConfig"
        ]
        return result

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["CodeSigningConfig"]["CodeSigningConfigArn"]
            resource["Properties"]["CodeSigningConfigArn"] = result["CodeSigningConfig"][
                "CodeSigningConfigArn"
            ]

        return {
            "create": {"function": "create_code_signing_config", "result_handler": _handle_result},
            "delete": {
                "function": "delete_code_signing_config",
                "parameters": {
                    "CodeSigningConfigArn": "CodeSigningConfigArn",
                },
            },
        }


# TODO: test
class LambdaLayerVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::LayerVersion"

    def fetch_state(self, stack_name, resources):
        layer_name = self.props.get("LayerName")
        # TODO extract region name if layer_name is an ARN
        client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).lambda_
        layers = client.list_layer_versions(LayerName=layer_name).get("LayerVersions", [])
        return layers[-1] if layers else None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        resource["Properties"]["LayerName"] = (
            resource["Properties"].get("LayerName") or f"layer-{short_uid()}"
        )

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["LayerVersionArn"]

        return {"create": {"function": "publish_layer_version", "result_handler": _handle_result}}


# TODO: test
# TODO: remove inheritance
class LambdaLayerVersionPermission(LambdaPermission):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::LayerVersionPermission"

    def fetch_state(self, stack_name, resources):
        props = self.props
        props["LayerVersionArn"] = props["LayerVersionArn"]
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
        def layer_permission_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            layer_name, version_number = cls.layer_name_and_version(properties)
            result = select_attributes(properties, ["Action", "Principal"])
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
