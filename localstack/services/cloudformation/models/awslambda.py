import os

from localstack.services.awslambda.lambda_api import get_lambda_policy_name
from localstack.services.awslambda.lambda_utils import get_handler_file_from_name
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    get_cfn_response_mod_file,
    select_parameters,
)
from localstack.services.cloudformation.service_models import LOG, REF_ID_ATTRS, GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    cp_r,
    is_base64,
    is_zip_file,
    mkdir,
    new_tmp_dir,
    rm_rf,
    save_file,
    select_attributes,
    short_uid,
    to_bytes,
)
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
            return aws_stack.lambda_function_arn(func_name)
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
            cfn_response_tmp_file = get_cfn_response_mod_file()
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
            },
            "delete": {"function": "delete_function", "parameters": get_delete_params},
        }


class LambdaFunctionVersion(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Version"

    def fetch_state(self, stack_name, resources):
        name = self.resolve_refs_recursively(stack_name, self.props.get("FunctionName"), resources)
        if not name:
            return None
        func_name = aws_stack.lambda_function_name(name)
        func_version = name.split(":")[7] if len(name.split(":")) > 7 else "$LATEST"
        versions = aws_stack.connect_to_service("lambda").list_versions_by_function(
            FunctionName=func_name
        )
        return ([v for v in versions["Versions"] if v["Version"] == func_version] or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "publish_version",
                "parameters": select_parameters("FunctionName", "CodeSha256", "Description"),
            }
        }

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return "%s:%s" % (
            self.props.get("FunctionArn"),
            self.props.get("Version").split(":")[-1],
        )


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
        return {"create": {"function": "create_event_source_mapping"}}


class LambdaPermission(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::Permission"

    def fetch_state(self, stack_name, resources):
        props = self.props
        func_name = self.resolve_refs_recursively(stack_name, props.get("FunctionName"), resources)
        func_arn = aws_stack.lambda_function_arn(func_name)
        return self.do_fetch_state(func_name, func_arn)

    def do_fetch_state(self, resource_name, resource_arn):
        iam = aws_stack.connect_to_service("iam")
        props = self.props
        policy_name = get_lambda_policy_name(resource_name)
        policy_arn = aws_stack.policy_arn(policy_name)
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version = policy.get("DefaultVersionId")
        policy = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)["PolicyVersion"]
        statements = policy["Document"]["Statement"]
        statements = statements if isinstance(statements, list) else [statements]
        principal = props.get("Principal")
        existing = [
            s
            for s in statements
            if s["Action"] == props["Action"]
            and s["Resource"] == resource_arn
            and (
                not principal
                or s["Principal"] in [principal, {"Service": principal}, {"Service": [principal]}]
            )
        ]
        return existing[0] if existing else None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        # return statement ID here to indicate that the resource has been deployed
        return self.props.get("Sid")

    @staticmethod
    def get_deploy_templates():
        def lambda_permission_params(params, **kwargs):
            result = select_parameters("FunctionName", "Action", "Principal")(params, **kwargs)
            result["StatementId"] = short_uid()
            return result

        return {
            "create": {
                "function": "add_permission",
                "parameters": lambda_permission_params,
            }
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
