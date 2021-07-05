import json
import logging
import time
import traceback

from requests.models import Request

from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str
from localstack.utils.persistence import PersistingProxyListener

ACTION_PUT_PARAM = "AmazonSSM.PutParameter"
ACTION_GET_PARAM = "AmazonSSM.GetParameter"
ACTION_GET_PARAMS = "AmazonSSM.GetParameters"
ACTION_GET_PARAMS_BY_PATH = "AmazonSSM.GetParametersByPath"

# logger
LOG = logging.getLogger(__name__)


def normalize_name(param_name):
    param_name = param_name.strip("/")
    param_name = param_name.replace("//", "/")
    if "/" in param_name:
        param_name = "/%s" % param_name
    return param_name


def get_secrets_information(name, resource_name):
    client = aws_stack.connect_to_service("secretsmanager")
    try:
        secret_info = client.get_secret_value(SecretId=resource_name)

        del secret_info["ResponseMetadata"]
        created_date_timestamp = time.mktime(secret_info["CreatedDate"].timetuple())
        secret_info["CreatedDate"] = created_date_timestamp
        result = {
            "Parameter": {
                "SourceResult": json.dumps(secret_info, default=str),
                "Name": name,
                "Value": secret_info.get("SecretString"),
                "Type": "SecureString",
                "LastModifiedDate": created_date_timestamp,
            }
        }
        return result
    except client.exceptions.ResourceNotFoundException:
        return None


def has_secrets(names):
    for name in names:
        if name.startswith("/aws/reference/secretsmanager"):
            return True


def get_params_and_secrets(names):
    ssm_client = aws_stack.connect_to_service("ssm")
    result = {"Parameters": [], "InvalidParameters": []}
    secrets_prefix = "/aws/reference/secretsmanager"

    for name in names:
        if name.startswith(secrets_prefix):
            secret = get_secrets_information(name, name[len(secrets_prefix) + 1 :])
            if secret is not None:
                secret = secret["Parameter"]
                result["Parameters"].append(secret)
            else:
                result["InvalidParameters"].append(name)
        else:
            try:
                param = ssm_client.get_parameter(Name=name)
                param["Parameter"]["LastModifiedDate"] = time.mktime(
                    param["Parameter"]["LastModifiedDate"].timetuple()
                )
                result["Parameters"].append(param["Parameter"])
            except ssm_client.exceptions.ParameterNotFound:
                result["InvalidParameters"].append(name)

    return result


def get_params_by_path_with_labels(
    path="", param_filters=None, labels_to_filter=None, recursive=False
):
    ssm_client = aws_stack.connect_to_service("ssm")
    result = {"Parameters": []}
    filters = [{"Key": "Path", "Values": [path]}]
    filters.extend(param_filters)
    if recursive:
        filters[0]["Option"] = "Recursive"

    def filter_by_label(param, labels):
        for label in param["Labels"]:
            if label in labels:
                return param

    try:
        # Get all the params in the path
        params_in_path = ssm_client.describe_parameters(ParameterFilters=filters)["Parameters"]

        # Get parameter with all its labels (for all the parameters in params_in_path)
        # Labels of the parameters can be obtained by calling get_parameter_history with parameter name
        all_params = []
        for params in params_in_path:
            all_params.extend(ssm_client.get_parameter_history(Name=params["Name"])["Parameters"])

        # Filter the params with matched labels
        filtered_params = list(
            filter(
                lambda param: filter_by_label(param=param, labels=labels_to_filter),
                all_params,
            )
        )

        # Get details of the filtered params to return
        # This step is needed because get_parameter_history doesn't return parameter's ARN
        details_of_filtered_params = list(
            map(
                lambda param: ssm_client.get_parameter(Name=param["Name"])["Parameter"],
                filtered_params,
            )
        )
        result["Parameters"].extend(details_of_filtered_params)
    except Exception as e:
        LOG.info(
            "Unable to get SSM parameters by path and filter by labels : %s %s"
            % (e, traceback.format_exc())
        )
        raise e
    return result


class ProxyListenerSSM(PersistingProxyListener):
    def api_name(self):
        return "ssm"

    def forward_request(self, method, path, data, headers):
        if method == "OPTIONS":
            return 200

        target = headers.get("X-Amz-Target")
        data_orig = data
        if method == "POST" and target:
            data = json.loads(to_str(data))
            if target == ACTION_GET_PARAMS:
                names = data["Names"] = data.get("Names") or []
                if has_secrets(names):
                    return get_params_and_secrets(names)
                else:
                    for i in range(len(names)):
                        names[i] = normalize_name(names[i])
            elif target in [ACTION_PUT_PARAM, ACTION_GET_PARAM]:
                name = data.get("Name") or ""
                data["Name"] = normalize_name(name)
                if target == ACTION_GET_PARAM:
                    details = name.split("/")
                    if len(details) > 4:
                        service = details[3]
                        if service == "secretsmanager":
                            resource_name = "/".join(details[4:])
                            secret = get_secrets_information(name, resource_name)
                            if secret is not None:
                                return secret
            elif target == ACTION_GET_PARAMS_BY_PATH and data.get("ParameterFilters"):
                params_filters = data.get("ParameterFilters") or []
                labels = []
                for filter in params_filters:
                    if filter["Key"] == "Label":
                        labels = filter["Values"]
                        params_filters.remove(filter)
                if labels:
                    path = data.get("Path")
                    recursive = data.get("Recursive") or False
                    return get_params_by_path_with_labels(
                        path=path,
                        param_filters=params_filters,
                        labels_to_filter=labels,
                        recursive=recursive,
                    )
            data = json.dumps(data)
            if data != data_orig:
                return Request(data=data, headers=headers, method=method)

        return True


# instantiate listener
UPDATE_SSM = ProxyListenerSSM()
