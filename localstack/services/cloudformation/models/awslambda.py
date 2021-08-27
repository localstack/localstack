import os

from localstack.services.awslambda.lambda_api import LAMBDA_POLICY_NAME_PATTERN
from localstack.services.awslambda.lambda_utils import get_handler_file_from_name
from localstack.services.cloudformation.deployment_utils import (
    get_cfn_response_mod_file,
    select_parameters,
)
from localstack.services.cloudformation.service_models import LOG, GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import cp_r, is_base64, mkdir, new_tmp_dir, rm_rf, save_file, short_uid
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
        keys = (
            "FunctionName",
            "Role",
            "Handler",
            "Description",
            "Timeout",
            "MemorySize",
            "Environment",
            "Runtime",
        )
        update_props = dict([(k, props[k]) for k in keys if k in props])
        update_props = self.resolve_refs_recursively(stack_name, update_props, resources)
        if "Timeout" in update_props:
            update_props["Timeout"] = int(update_props["Timeout"])
        if "Code" in props:
            code = props["Code"] or {}
            if not code.get("ZipFile"):
                LOG.debug(
                    'Updating code for Lambda "%s" from location: %s'
                    % (props["FunctionName"], code)
                )
            client.update_function_code(FunctionName=props["FunctionName"], **code)
        if "Environment" in update_props:
            environment_variables = update_props["Environment"].get("Variables", {})
            update_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }
        return client.update_function_configuration(**update_props)

    @staticmethod
    def get_deploy_templates():
        def get_lambda_code_param(params, **kwargs):
            code = params.get("Code", {})
            zip_file = code.get("ZipFile")
            if zip_file and not is_base64(zip_file):
                tmp_dir = new_tmp_dir()
                handler_file = get_handler_file_from_name(
                    params["Handler"], runtime=params["Runtime"]
                )
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
            return code

        def get_delete_params(params, **kwargs):
            return {"FunctionName": params.get("FunctionName")}

        return {
            "create": {
                "function": "create_function",
                "parameters": {
                    "FunctionName": "FunctionName",
                    "Runtime": "Runtime",
                    "Role": "Role",
                    "Handler": "Handler",
                    "Code": get_lambda_code_param,
                    "Description": "Description",
                    "Environment": "Environment",
                    "Timeout": "Timeout",
                    "MemorySize": "MemorySize",
                    "Layers": "Layers"
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


class LambdaEventSourceMapping(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Lambda::EventSourceMapping"

    def fetch_state(self, stack_name, resources):
        props = self.props
        resource_id = props["FunctionName"] or self.resource_id
        source_arn = props.get("EventSourceArn")
        resource_id = self.resolve_refs_recursively(stack_name, resource_id, resources)
        source_arn = self.resolve_refs_recursively(stack_name, source_arn, resources)
        if not resource_id or not source_arn:
            raise Exception("ResourceNotFound")
        mappings = aws_stack.connect_to_service("lambda").list_event_source_mappings(
            FunctionName=resource_id, EventSourceArn=source_arn
        )
        mapping = list(
            filter(
                lambda m: m["EventSourceArn"] == source_arn
                and m["FunctionArn"] == aws_stack.lambda_function_arn(resource_id),
                mappings["EventSourceMappings"],
            )
        )
        if not mapping:
            raise Exception("ResourceNotFound")
        return mapping[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("UUID")


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
        policy_name = LAMBDA_POLICY_NAME_PATTERN % resource_name
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
